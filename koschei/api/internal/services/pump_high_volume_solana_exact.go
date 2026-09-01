package services

import (
	"context"
	"strings"
	"time"
)

// ListPumpPortalCandidatesExact is the canonical selective-Pump candidate read.
// Solana base58 addresses are case-sensitive, so identity, dedupe and cursor
// ordering must never case-fold the mint. COLLATE "C" keeps the tie-break byte
// ordered and deterministic across database locale settings.
func (s *SecurityRadarStore) ListPumpPortalCandidatesExact(ctx context.Context, limit int, before time.Time, beforeTarget string) ([]PumpRadarCandidate, error) {
	if s == nil || s.DB == nil {
		return []PumpRadarCandidate{}, nil
	}
	if limit <= 0 || limit > 3000 {
		limit = defaultPumpHighVolumePageSize
	}
	condition := ""
	args := []any{limit}
	if !before.IsZero() {
		condition = `WHERE observed_at < $2 OR (observed_at = $2 AND mint COLLATE "C" < $3 COLLATE "C")`
		args = append(args, before.UTC(), strings.TrimSpace(beforeTarget))
	}
	query := `
		WITH latest AS (
			SELECT DISTINCT ON (target COLLATE "C")
				target AS mint,
				COALESCE(NULLIF(signals->>'token_name',''),NULLIF(raw_summary->>'name',''),'') AS name,
				COALESCE(NULLIF(signals->>'token_symbol',''),NULLIF(raw_summary->>'symbol',''),'') AS symbol,
				COALESCE(NULLIF(signals->>'creator_wallet',''),NULLIF(signals->>'creator',''),NULLIF(raw_summary->>'creator',''),'') AS creator,
				created_at AS observed_at
			FROM security_radar_events
			WHERE source='pumpportal' AND target_type='token' AND btrim(target)<>''
			ORDER BY target COLLATE "C", created_at DESC, id DESC
		)
		SELECT mint,name,symbol,creator,observed_at
		FROM latest
		` + condition + `
		ORDER BY observed_at DESC, mint COLLATE "C" DESC
		LIMIT $1`
	rows, err := s.DB.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PumpRadarCandidate{}
	for rows.Next() {
		var item PumpRadarCandidate
		if err := rows.Scan(&item.Mint, &item.Name, &item.Symbol, &item.Creator, &item.ObservedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

// PumpHighVolumeAttemptedRecentlyExact isolates retry suppression to the exact
// Solana mint. A case-variant address must not suppress another mint's report.
func (s *SecurityRadarStore) PumpHighVolumeAttemptedRecentlyExact(ctx context.Context, mint string, cooldown time.Duration) (bool, error) {
	if s == nil || s.DB == nil {
		return false, nil
	}
	mint = strings.TrimSpace(mint)
	if mint == "" {
		return false, nil
	}
	if cooldown <= 0 {
		cooldown = defaultPumpHighVolumeAttemptPause
	}
	var exists bool
	err := s.DB.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM security_radar_events
			WHERE event_type=$1 AND source=$2 AND target=$3
			  AND COALESCE(signals->>'auto_scan_attempted','false')='true'
			  AND updated_at >= now()-($4 * interval '1 second')
		)`, pumpHighVolumeEventType, PumpHighVolumeCanonicalSource, mint, int64(cooldown/time.Second)).Scan(&exists)
	return exists, err
}
