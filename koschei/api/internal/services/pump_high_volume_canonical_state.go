package services

import (
	"context"
	"strings"
	"time"
)

const (
	PumpHighVolumeCanonicalMode   = "background_pump_high_volume"
	PumpHighVolumeCanonicalSource = pumpHighVolumeSource
)

// PumpHighVolumeCanonicalReportCompletedRecently answers the scheduling question
// from the canonical investigation job ledger. A legacy final_verdict_engine row
// is not a completion authority: the bounded Pump scheduler queues a canonical
// investigation, and only that job reaching completed proves the report ran.
// Solana mint addresses are case-sensitive, so target matching is exact.
func (s *SecurityRadarStore) PumpHighVolumeCanonicalReportCompletedRecently(ctx context.Context, mint string, cooldown time.Duration) (bool, error) {
	if s == nil || s.DB == nil {
		return false, nil
	}
	mint = strings.TrimSpace(mint)
	if mint == "" {
		return false, nil
	}
	if cooldown <= 0 {
		cooldown = defaultPumpHighVolumeCooldown
	}
	var exists bool
	err := s.DB.QueryRowContext(ctx, `
		SELECT EXISTS (
			SELECT 1
			FROM web3_jobs
			WHERE job_type='canonical_investigation'
			  AND status='completed'
			  AND network='solana-mainnet'
			  AND target=$1
			  AND COALESCE(request_payload->>'source','')=$2
			  AND COALESCE(request_payload->>'mode','')=$3
			  AND completed_at IS NOT NULL
			  AND completed_at >= now()-($4 * interval '1 second')
		)`, mint, PumpHighVolumeCanonicalSource, PumpHighVolumeCanonicalMode, int64(cooldown/time.Second)).Scan(&exists)
	return exists, err
}
