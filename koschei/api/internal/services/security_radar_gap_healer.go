package services

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

type securityRadarGapHealer struct {
	Store      *SecurityRadarStore
	RPCURL     string
	Network    string
	PollEvery  time.Duration
	PageSize   int
	MaxPages   int
	HTTPClient *http.Client
}

type securityRadarReplayCursor struct {
	Network             string
	ProgramID           string
	ModuleID            string
	EventType           string
	WatermarkSignature  string
	WatermarkSlot       int64
	ScanHeadSignature   string
	ScanHeadSlot        int64
	ScanBeforeSignature string
	Status              string
	RecoveredEventCount int64
	SkippedFailedCount  int64
	LastError           string
}

type securityRadarReplaySignature struct {
	Signature          string          `json:"signature"`
	Slot               int64           `json:"slot"`
	Err                json.RawMessage `json:"err"`
	ConfirmationStatus string          `json:"confirmationStatus"`
}

type securityRadarReplayPagePlan struct {
	Replay           []securityRadarReplaySignature
	ReachedWatermark bool
	NextBefore       string
	HeadSignature    string
	HeadSlot         int64
}

func securityRadarGapHealerEnabled() bool {
	return envBool("KOSCHEI_SLOT_GAP_HEALER_ENABLED")
}

func newSecurityRadarGapHealer(store *SecurityRadarStore, rpcURL, network string) *securityRadarGapHealer {
	pollSeconds := boundedSecurityRadarEnvInt("KOSCHEI_SLOT_GAP_HEALER_INTERVAL_SECONDS", 60, 30, 900)
	pageSize := boundedSecurityRadarEnvInt("KOSCHEI_SLOT_GAP_HEALER_PAGE_SIZE", 500, 10, 1000)
	maxPages := boundedSecurityRadarEnvInt("KOSCHEI_SLOT_GAP_HEALER_MAX_PAGES_PER_CYCLE", 4, 1, 20)
	return &securityRadarGapHealer{
		Store:      store,
		RPCURL:     strings.TrimSpace(rpcURL),
		Network:    firstRadarValue(network, "solana-mainnet"),
		PollEvery:  time.Duration(pollSeconds) * time.Second,
		PageSize:   pageSize,
		MaxPages:   maxPages,
		HTTPClient: http.DefaultClient,
	}
}

func (h *securityRadarGapHealer) Start(ctx context.Context) {
	if h == nil || h.Store == nil || h.Store.DB == nil || strings.TrimSpace(h.RPCURL) == "" || !securityRadarGapHealerEnabled() {
		return
	}
	log.Printf("security radar slot gap healer started network=%s interval=%s page_size=%d max_pages=%d watermark=independent", h.Network, h.PollEvery, h.PageSize, h.MaxPages)
	h.RunOnce(ctx)
	ticker := time.NewTicker(h.PollEvery)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("security radar slot gap healer stopped")
			return
		case <-ticker.C:
			h.RunOnce(ctx)
		}
	}
}

func (h *securityRadarGapHealer) RunOnce(ctx context.Context) {
	if h == nil || h.Store == nil || h.Store.DB == nil || strings.TrimSpace(h.RPCURL) == "" {
		return
	}
	for _, source := range arvisHeartbeatSources() {
		if ctx.Err() != nil {
			return
		}
		if strings.TrimSpace(source.ProgramID) == "" {
			continue
		}
		if err := h.healSource(ctx, source); err != nil && ctx.Err() == nil {
			if isUndefinedTableError(err) {
				log.Printf("security radar slot gap healer paused: replay cursor migration is not applied")
				return
			}
			log.Printf("security radar slot gap healer source=%s failed: %s", source.Label, safeProviderError(err))
		}
	}
}

func (h *securityRadarGapHealer) healSource(ctx context.Context, source arvisHeartbeatSource) error {
	cursor, exists, err := h.loadCursor(ctx, source)
	if err != nil {
		return err
	}
	if !exists || strings.TrimSpace(cursor.WatermarkSignature) == "" {
		return h.bootstrapCursor(ctx, source)
	}

	for pageIndex := 0; pageIndex < h.MaxPages; pageIndex++ {
		pageCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		page, fetchErr := h.fetchSignaturePage(pageCtx, source.ProgramID, cursor.ScanBeforeSignature, h.PageSize)
		cancel()
		if fetchErr != nil {
			_ = h.markCursorError(ctx, cursor, source, "rpc_error", compactRadarError("getSignaturesForAddress", fetchErr))
			return fetchErr
		}
		if len(page) == 0 {
			if strings.TrimSpace(cursor.ScanBeforeSignature) == "" {
				return h.touchCaughtUp(ctx, cursor, source)
			}
			return h.markCursorError(ctx, cursor, source, "blocked_history_boundary", "Replay pagination ended before the prior recovery watermark was reached.")
		}

		plan := planSecurityRadarReplayPage(cursor, page, h.PageSize)
		if strings.TrimSpace(cursor.ScanHeadSignature) == "" {
			cursor.ScanHeadSignature = plan.HeadSignature
			cursor.ScanHeadSlot = plan.HeadSlot
		}

		recovered, skippedFailed, insertErr := h.persistReplayEntries(ctx, source, plan.Replay)
		if insertErr != nil {
			_ = h.markCursorError(ctx, cursor, source, "rpc_error", insertErr.Error())
			return insertErr
		}

		if plan.ReachedWatermark {
			return h.advanceCursor(ctx, cursor, source, recovered, skippedFailed)
		}
		if strings.TrimSpace(plan.NextBefore) == "" {
			return h.markCursorProgress(ctx, cursor, source, "blocked_history_boundary", "", recovered, skippedFailed,
				"Available signature history ended before the prior recovery watermark was reached.")
		}
		if err := h.markCursorProgress(ctx, cursor, source, "backfilling", plan.NextBefore, recovered, skippedFailed, ""); err != nil {
			return err
		}
		cursor.ScanBeforeSignature = plan.NextBefore
		cursor.Status = "backfilling"
	}
	return nil
}

func (h *securityRadarGapHealer) bootstrapCursor(ctx context.Context, source arvisHeartbeatSource) error {
	pageCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	page, err := h.fetchSignaturePage(pageCtx, source.ProgramID, "", 1)
	cancel()
	if err != nil {
		return err
	}
	status := "waiting_for_head"
	watermarkSignature := ""
	watermarkSlot := int64(0)
	if len(page) > 0 {
		status = "caught_up"
		watermarkSignature = strings.TrimSpace(page[0].Signature)
		watermarkSlot = page[0].Slot
	}
	_, err = h.Store.DB.ExecContext(ctx, `
		INSERT INTO security_radar_replay_cursors
		(network,program_id,module_id,event_type,watermark_signature,watermark_slot,status,last_error,last_scan_at,created_at,updated_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,'',now(),now(),now())
		ON CONFLICT(network,program_id) DO UPDATE SET
			module_id=EXCLUDED.module_id,
			event_type=EXCLUDED.event_type,
			watermark_signature=CASE WHEN security_radar_replay_cursors.watermark_signature='' THEN EXCLUDED.watermark_signature ELSE security_radar_replay_cursors.watermark_signature END,
			watermark_slot=CASE WHEN security_radar_replay_cursors.watermark_signature='' THEN EXCLUDED.watermark_slot ELSE security_radar_replay_cursors.watermark_slot END,
			status=CASE WHEN security_radar_replay_cursors.watermark_signature='' THEN EXCLUDED.status ELSE security_radar_replay_cursors.status END,
			last_error='',last_scan_at=now(),updated_at=now()
	`, h.Network, source.ProgramID, source.ModuleID, source.EventType, watermarkSignature, watermarkSlot, status)
	return err
}

func (h *securityRadarGapHealer) loadCursor(ctx context.Context, source arvisHeartbeatSource) (securityRadarReplayCursor, bool, error) {
	var cursor securityRadarReplayCursor
	err := h.Store.DB.QueryRowContext(ctx, `
		SELECT network,program_id,module_id,event_type,watermark_signature,watermark_slot,
		       scan_head_signature,scan_head_slot,scan_before_signature,status,
		       recovered_event_count,skipped_failed_count,last_error
		FROM security_radar_replay_cursors
		WHERE network=$1 AND program_id=$2
	`, h.Network, source.ProgramID).Scan(
		&cursor.Network, &cursor.ProgramID, &cursor.ModuleID, &cursor.EventType,
		&cursor.WatermarkSignature, &cursor.WatermarkSlot,
		&cursor.ScanHeadSignature, &cursor.ScanHeadSlot, &cursor.ScanBeforeSignature,
		&cursor.Status, &cursor.RecoveredEventCount, &cursor.SkippedFailedCount, &cursor.LastError,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return securityRadarReplayCursor{}, false, nil
	}
	return cursor, err == nil, err
}

func (h *securityRadarGapHealer) fetchSignaturePage(ctx context.Context, programID, before string, limit int) ([]securityRadarReplaySignature, error) {
	if h == nil || strings.TrimSpace(h.RPCURL) == "" {
		return nil, errors.New("gap healer RPC URL unavailable")
	}
	if limit <= 0 || limit > 1000 {
		limit = 500
	}
	config := map[string]any{"limit": limit, "commitment": "confirmed"}
	if strings.TrimSpace(before) != "" {
		config["before"] = strings.TrimSpace(before)
	}
	payload, err := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "getSignaturesForAddress",
		"params":  []any{strings.TrimSpace(programID), config},
	})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.RPCURL, bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	client := h.HTTPClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("gap healer RPC status %d", resp.StatusCode)
	}
	var envelope struct {
		Result []securityRadarReplaySignature `json:"result"`
		Error  *struct {
			Code    int    `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	decoder := json.NewDecoder(io.LimitReader(resp.Body, 4<<20))
	if err := decoder.Decode(&envelope); err != nil {
		return nil, err
	}
	if envelope.Error != nil {
		return nil, fmt.Errorf("gap healer RPC error %d: %s", envelope.Error.Code, strings.TrimSpace(envelope.Error.Message))
	}
	return envelope.Result, nil
}

func planSecurityRadarReplayPage(cursor securityRadarReplayCursor, page []securityRadarReplaySignature, pageSize int) securityRadarReplayPagePlan {
	plan := securityRadarReplayPagePlan{Replay: []securityRadarReplaySignature{}}
	if len(page) == 0 {
		return plan
	}
	plan.HeadSignature = cursor.ScanHeadSignature
	plan.HeadSlot = cursor.ScanHeadSlot
	if strings.TrimSpace(plan.HeadSignature) == "" {
		plan.HeadSignature = strings.TrimSpace(page[0].Signature)
		plan.HeadSlot = page[0].Slot
	}
	for _, item := range page {
		signature := strings.TrimSpace(item.Signature)
		if signature == "" {
			continue
		}
		if strings.TrimSpace(cursor.WatermarkSignature) != "" && signature == strings.TrimSpace(cursor.WatermarkSignature) {
			plan.ReachedWatermark = true
			break
		}
		// If the exact watermark signature disappeared because of provider/fork
		// differences, consume the complete watermark slot before stopping. This
		// prevents same-slot transactions after the old cursor from being skipped.
		if cursor.WatermarkSlot > 0 && item.Slot < cursor.WatermarkSlot {
			plan.ReachedWatermark = true
			break
		}
		plan.Replay = append(plan.Replay, item)
	}
	if !plan.ReachedWatermark && len(page) >= pageSize {
		plan.NextBefore = strings.TrimSpace(page[len(page)-1].Signature)
	}
	return plan
}

func (h *securityRadarGapHealer) persistReplayEntries(ctx context.Context, source arvisHeartbeatSource, entries []securityRadarReplaySignature) (int64, int64, error) {
	var recovered int64
	var skippedFailed int64
	for i := len(entries) - 1; i >= 0; i-- {
		entry := entries[i]
		signature := strings.TrimSpace(entry.Signature)
		if signature == "" {
			continue
		}
		if replaySignatureFailed(entry.Err) {
			skippedFailed++
			continue
		}
		exists, err := securityRadarStreamSignatureExists(ctx, h.Store.DB, signature, source.ProgramID)
		if err != nil {
			return recovered, skippedFailed, err
		}
		if exists {
			continue
		}
		_, err = h.Store.InsertStreamEvent(ctx, SecurityRadarStreamEventRecord{
			Provider:        "solana_rpc_gap_healer",
			StreamMode:      "gap_replay",
			Network:         h.Network,
			ModuleID:        source.ModuleID,
			EventType:       source.EventType,
			Target:          signature,
			TargetType:      "signature",
			Signature:       signature,
			Slot:            entry.Slot,
			ProgramID:       source.ProgramID,
			EvidenceQuality: "replay_signature_observed",
			Decoded: map[string]any{
				"source":              source.Label,
				"module_id":           source.ModuleID,
				"program_id":          source.ProgramID,
				"rpc_method":          "getSignaturesForAddress",
				"recovery_mode":       "independent_watermark_replay",
				"confirmation_status": entry.ConfirmationStatus,
				"requires_enrichment": true,
			},
			RawEvent: map[string]any{
				"signature": signature,
				"slot":      entry.Slot,
				"source":    source.Label,
				"replayed":  true,
			},
		})
		if err != nil {
			return recovered, skippedFailed, err
		}
		recovered++
	}
	return recovered, skippedFailed, nil
}

func securityRadarStreamSignatureExists(ctx context.Context, db *sql.DB, signature, programID string) (bool, error) {
	if db == nil || strings.TrimSpace(signature) == "" || strings.TrimSpace(programID) == "" {
		return false, nil
	}
	var exists bool
	err := db.QueryRowContext(ctx, `
		SELECT EXISTS(
			SELECT 1 FROM security_radar_stream_events
			WHERE signature=$1 AND program_id=$2
		)
	`, strings.TrimSpace(signature), strings.TrimSpace(programID)).Scan(&exists)
	return exists, err
}

func replaySignatureFailed(raw json.RawMessage) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "null"
}

func (h *securityRadarGapHealer) advanceCursor(ctx context.Context, cursor securityRadarReplayCursor, source arvisHeartbeatSource, recovered, skippedFailed int64) error {
	headSignature := strings.TrimSpace(cursor.ScanHeadSignature)
	headSlot := cursor.ScanHeadSlot
	if headSignature == "" {
		headSignature = strings.TrimSpace(cursor.WatermarkSignature)
		headSlot = cursor.WatermarkSlot
	}
	_, err := h.Store.DB.ExecContext(ctx, `
		UPDATE security_radar_replay_cursors
		SET module_id=$3,event_type=$4,
		    watermark_signature=$5,watermark_slot=$6,
		    scan_head_signature='',scan_head_slot=0,scan_before_signature='',
		    status='caught_up',
		    recovered_event_count=recovered_event_count+$7,
		    skipped_failed_count=skipped_failed_count+$8,
		    last_error='',last_scan_at=now(),updated_at=now()
		WHERE network=$1 AND program_id=$2
	`, h.Network, source.ProgramID, source.ModuleID, source.EventType, headSignature, headSlot, recovered, skippedFailed)
	return err
}

func (h *securityRadarGapHealer) markCursorProgress(ctx context.Context, cursor securityRadarReplayCursor, source arvisHeartbeatSource, status, nextBefore string, recovered, skippedFailed int64, message string) error {
	headSignature := strings.TrimSpace(cursor.ScanHeadSignature)
	headSlot := cursor.ScanHeadSlot
	_, err := h.Store.DB.ExecContext(ctx, `
		UPDATE security_radar_replay_cursors
		SET module_id=$3,event_type=$4,
		    scan_head_signature=$5,scan_head_slot=$6,scan_before_signature=$7,
		    status=$8,
		    recovered_event_count=recovered_event_count+$9,
		    skipped_failed_count=skipped_failed_count+$10,
		    last_error=$11,last_scan_at=now(),updated_at=now()
		WHERE network=$1 AND program_id=$2
	`, h.Network, source.ProgramID, source.ModuleID, source.EventType, headSignature, headSlot,
		strings.TrimSpace(nextBefore), status, recovered, skippedFailed, trimGapHealerError(message))
	return err
}

func (h *securityRadarGapHealer) markCursorError(ctx context.Context, cursor securityRadarReplayCursor, source arvisHeartbeatSource, status, message string) error {
	if status == "" {
		status = "rpc_error"
	}
	_, err := h.Store.DB.ExecContext(ctx, `
		UPDATE security_radar_replay_cursors
		SET module_id=$3,event_type=$4,status=$5,last_error=$6,last_scan_at=now(),updated_at=now()
		WHERE network=$1 AND program_id=$2
	`, h.Network, source.ProgramID, source.ModuleID, source.EventType, status, trimGapHealerError(message))
	return err
}

func (h *securityRadarGapHealer) touchCaughtUp(ctx context.Context, cursor securityRadarReplayCursor, source arvisHeartbeatSource) error {
	_, err := h.Store.DB.ExecContext(ctx, `
		UPDATE security_radar_replay_cursors
		SET module_id=$3,event_type=$4,status='caught_up',last_error='',last_scan_at=now(),updated_at=now()
		WHERE network=$1 AND program_id=$2
	`, h.Network, source.ProgramID, source.ModuleID, source.EventType)
	return err
}

func trimGapHealerError(message string) string {
	message = strings.TrimSpace(message)
	if len(message) > 500 {
		return message[:500]
	}
	return message
}

func init() {
	_ = os.Getenv("KOSCHEI_SLOT_GAP_HEALER_ENABLED")
}
