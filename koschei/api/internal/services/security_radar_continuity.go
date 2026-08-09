package services

import (
	"context"
	"database/sql"
	"sort"
	"strings"
	"time"
)

type SecurityRadarContinuitySource struct {
	Network             string    `json:"network"`
	ProgramID           string    `json:"program_id"`
	ModuleID            string    `json:"module_id"`
	EventType           string    `json:"event_type"`
	Status              string    `json:"status"`
	WatermarkSignature  string    `json:"watermark_signature,omitempty"`
	WatermarkSlot       int64     `json:"watermark_slot"`
	ScanHeadSignature   string    `json:"scan_head_signature,omitempty"`
	ScanHeadSlot        int64     `json:"scan_head_slot"`
	ScanBeforeSignature string    `json:"scan_before_signature,omitempty"`
	RecoveredEvents     int64     `json:"recovered_events"`
	SkippedFailed       int64     `json:"skipped_failed"`
	LastError           string    `json:"last_error,omitempty"`
	LastScanAt          time.Time `json:"last_scan_at,omitempty"`
	UpdatedAt           time.Time `json:"updated_at"`
}

type SecurityRadarContinuityReport struct {
	Available       bool                            `json:"available"`
	Status          string                          `json:"status"`
	AllCaughtUp     bool                            `json:"all_caught_up"`
	SourceCount     int                             `json:"source_count"`
	CaughtUpCount   int                             `json:"caught_up_count"`
	RecoveringCount int                             `json:"recovering_count"`
	BlockedCount    int                             `json:"blocked_count"`
	RPCErrorCount   int                             `json:"rpc_error_count"`
	RecoveredEvents int64                           `json:"recovered_events"`
	SkippedFailed   int64                           `json:"skipped_failed"`
	Sources         []SecurityRadarContinuitySource `json:"sources"`
	Policy          map[string]any                  `json:"policy"`
}

func LoadSecurityRadarContinuity(ctx context.Context, db *sql.DB) (SecurityRadarContinuityReport, error) {
	if db == nil {
		return summarizeSecurityRadarContinuity(nil), nil
	}
	rows, err := db.QueryContext(ctx, `
		SELECT network,program_id,module_id,event_type,status,
		       watermark_signature,watermark_slot,scan_head_signature,scan_head_slot,
		       scan_before_signature,recovered_event_count,skipped_failed_count,last_error,
		       last_scan_at,updated_at
		FROM security_radar_replay_cursors
		ORDER BY network,module_id,program_id
	`)
	if err != nil {
		return SecurityRadarContinuityReport{}, err
	}
	defer rows.Close()

	items := []SecurityRadarContinuitySource{}
	for rows.Next() {
		var item SecurityRadarContinuitySource
		var lastScan sql.NullTime
		if err := rows.Scan(
			&item.Network, &item.ProgramID, &item.ModuleID, &item.EventType, &item.Status,
			&item.WatermarkSignature, &item.WatermarkSlot, &item.ScanHeadSignature, &item.ScanHeadSlot,
			&item.ScanBeforeSignature, &item.RecoveredEvents, &item.SkippedFailed, &item.LastError,
			&lastScan, &item.UpdatedAt,
		); err != nil {
			return SecurityRadarContinuityReport{}, err
		}
		if lastScan.Valid {
			item.LastScanAt = lastScan.Time.UTC()
		}
		items = append(items, item)
	}
	if err := rows.Err(); err != nil {
		return SecurityRadarContinuityReport{}, err
	}
	return summarizeSecurityRadarContinuity(items), nil
}

func summarizeSecurityRadarContinuity(items []SecurityRadarContinuitySource) SecurityRadarContinuityReport {
	out := SecurityRadarContinuityReport{
		Status: "unavailable",
		Sources: append([]SecurityRadarContinuitySource{}, items...),
		Policy: map[string]any{
			"live_head_never_advances_recovery_watermark": true,
			"watermark_advances_only_after_boundary":      true,
			"same_slot_replay_before_boundary_close":      true,
			"blocked_history_is_not_reported_caught_up":   true,
			"continuity_is_not_chain_finality_guarantee":  true,
		},
	}
	if len(out.Sources) == 0 {
		return out
	}
	out.Available = true
	out.SourceCount = len(out.Sources)
	sort.SliceStable(out.Sources, func(i, j int) bool {
		if out.Sources[i].Network != out.Sources[j].Network {
			return out.Sources[i].Network < out.Sources[j].Network
		}
		if out.Sources[i].ModuleID != out.Sources[j].ModuleID {
			return out.Sources[i].ModuleID < out.Sources[j].ModuleID
		}
		return out.Sources[i].ProgramID < out.Sources[j].ProgramID
	})
	for i := range out.Sources {
		status := strings.ToLower(strings.TrimSpace(out.Sources[i].Status))
		out.RecoveredEvents += out.Sources[i].RecoveredEvents
		out.SkippedFailed += out.Sources[i].SkippedFailed
		switch status {
		case "caught_up":
			out.CaughtUpCount++
		case "blocked_history_boundary":
			out.BlockedCount++
		case "rpc_error":
			out.RPCErrorCount++
		default:
			out.RecoveringCount++
		}
	}
	out.AllCaughtUp = out.CaughtUpCount == out.SourceCount
	switch {
	case out.BlockedCount > 0:
		out.Status = "blocked"
	case out.RPCErrorCount > 0:
		out.Status = "degraded"
	case out.RecoveringCount > 0:
		out.Status = "recovering"
	case out.AllCaughtUp:
		out.Status = "caught_up"
	default:
		out.Status = "unknown"
	}
	return out
}
