package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"
)

// ensureSecurityRadarReplayAnchors closes the bootstrap race between reading the
// current Solana program head and starting WSS subscriptions. A recovery
// watermark may be created only from a signature that is already durable in the
// stream ledger. If the ledger has no anchor yet, the current RPC head is first
// persisted as an immutable replay anchor and only then becomes the watermark.
func ensureSecurityRadarReplayAnchors(ctx context.Context, healer *securityRadarGapHealer) error {
	if healer == nil || healer.Store == nil || healer.Store.DB == nil {
		return errors.New("gap healer store unavailable")
	}
	for _, source := range arvisHeartbeatSources() {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if strings.TrimSpace(source.ProgramID) == "" {
			continue
		}
		cursor, exists, err := healer.loadCursor(ctx, source)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		if exists && strings.TrimSpace(cursor.WatermarkSignature) != "" {
			continue
		}

		signature, slot, ok, err := latestDurableReplayAnchor(ctx, healer.Store.DB, healer.Network, source.ProgramID)
		if err != nil {
			return err
		}
		if !ok {
			pageCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			page, fetchErr := healer.fetchSignaturePage(pageCtx, source.ProgramID, "", 1)
			cancel()
			if fetchErr != nil {
				return fetchErr
			}
			if len(page) == 0 || strings.TrimSpace(page[0].Signature) == "" {
				return fmt.Errorf("no durable or RPC replay anchor available for %s", source.Label)
			}
			signature = strings.TrimSpace(page[0].Signature)
			slot = page[0].Slot
			if _, err := healer.Store.InsertStreamEvent(ctx, SecurityRadarStreamEventRecord{
				Provider:        "solana_rpc_gap_healer",
				StreamMode:      "gap_bootstrap_anchor",
				Network:         healer.Network,
				ModuleID:        source.ModuleID,
				EventType:       source.EventType,
				Target:          signature,
				TargetType:      "signature",
				Signature:       signature,
				Slot:            slot,
				ProgramID:       source.ProgramID,
				EvidenceQuality: "replay_bootstrap_anchor",
				Decoded: map[string]any{
					"source":              source.Label,
					"rpc_method":          "getSignaturesForAddress",
					"recovery_mode":       "durable_bootstrap_anchor",
					"transaction_failed":  replaySignatureFailed(page[0].Err),
					"confirmation_status": page[0].ConfirmationStatus,
				},
				RawEvent: map[string]any{
					"signature": signature,
					"slot":      slot,
					"anchor":    true,
				},
			}); err != nil {
				return err
			}
			// Read the anchor back from the durable ledger before advancing the
			// watermark. This turns DB persistence, not an RPC response, into the
			// bootstrap commit point.
			persistedSignature, persistedSlot, persisted, err := latestDurableReplayAnchor(ctx, healer.Store.DB, healer.Network, source.ProgramID)
			if err != nil {
				return err
			}
			if !persisted || persistedSignature != signature {
				return fmt.Errorf("bootstrap replay anchor was not durable for %s", source.Label)
			}
			slot = persistedSlot
		}

		if err := upsertDurableReplayWatermark(ctx, healer.Store.DB, healer.Network, source, signature, slot); err != nil {
			return err
		}
	}
	return nil
}

func latestDurableReplayAnchor(ctx context.Context, db *sql.DB, network, programID string) (string, int64, bool, error) {
	if db == nil {
		return "", 0, false, errors.New("database unavailable")
	}
	var signature string
	var slot int64
	err := db.QueryRowContext(ctx, `
		SELECT COALESCE(signature,''),COALESCE(slot,0)
		FROM security_radar_stream_events
		WHERE network=$1
		  AND program_id=$2
		  AND signature IS NOT NULL
		  AND btrim(signature)<>''
		ORDER BY COALESCE(slot,0) DESC,created_at DESC
		LIMIT 1
	`, normalizeRadarNetwork(network), strings.TrimSpace(programID)).Scan(&signature, &slot)
	if errors.Is(err, sql.ErrNoRows) {
		return "", 0, false, nil
	}
	if err != nil {
		return "", 0, false, err
	}
	return strings.TrimSpace(signature), slot, strings.TrimSpace(signature) != "", nil
}

func upsertDurableReplayWatermark(ctx context.Context, db *sql.DB, network string, source arvisHeartbeatSource, signature string, slot int64) error {
	if db == nil || strings.TrimSpace(signature) == "" {
		return errors.New("durable replay watermark requires a persisted signature")
	}
	var durable bool
	if err := db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM security_radar_stream_events
			WHERE network=$1 AND program_id=$2 AND signature=$3
		)
	`, normalizeRadarNetwork(network), strings.TrimSpace(source.ProgramID), strings.TrimSpace(signature)).Scan(&durable); err != nil {
		return err
	}
	if !durable {
		return errors.New("recovery watermark cannot advance to a non-durable signature")
	}
	_, err := db.ExecContext(ctx, `
		INSERT INTO security_radar_replay_cursors (
			network,program_id,module_id,event_type,watermark_signature,watermark_slot,
			status,last_error,last_scan_at,created_at,updated_at
		) VALUES ($1,$2,$3,$4,$5,$6,'caught_up','',now(),now(),now())
		ON CONFLICT(network,program_id) DO UPDATE SET
			module_id=EXCLUDED.module_id,
			event_type=EXCLUDED.event_type,
			watermark_signature=CASE
				WHEN security_radar_replay_cursors.watermark_signature='' THEN EXCLUDED.watermark_signature
				ELSE security_radar_replay_cursors.watermark_signature
			END,
			watermark_slot=CASE
				WHEN security_radar_replay_cursors.watermark_signature='' THEN EXCLUDED.watermark_slot
				ELSE security_radar_replay_cursors.watermark_slot
			END,
			status=CASE
				WHEN security_radar_replay_cursors.watermark_signature='' THEN 'caught_up'
				ELSE security_radar_replay_cursors.status
			END,
			last_error='',last_scan_at=now(),updated_at=now()
	`, normalizeRadarNetwork(network), strings.TrimSpace(source.ProgramID), source.ModuleID, source.EventType, strings.TrimSpace(signature), slot)
	return err
}
