package services

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

type PumpPortalInboxHealth struct {
	Available            bool       `json:"available"`
	Status               string     `json:"status"`
	PendingCount         int64      `json:"pending_count"`
	ProcessingCount      int64      `json:"processing_count"`
	RetryableCount       int64      `json:"retryable_count"`
	ExhaustedCount       int64      `json:"exhausted_count"`
	Completed24hCount    int64      `json:"completed_24h_count"`
	OpenCount            int64      `json:"open_count"`
	OldestOpenAgeSeconds int64      `json:"oldest_open_age_seconds"`
	OldestOpenAt         *time.Time `json:"oldest_open_at,omitempty"`
	LastReceivedAt       *time.Time `json:"last_received_at,omitempty"`
	Policy               map[string]any `json:"policy"`
}

func LoadPumpPortalInboxHealth(ctx context.Context, db *sql.DB, now time.Time) (PumpPortalInboxHealth, error) {
	out := PumpPortalInboxHealth{
		Status: "unavailable",
		Policy: map[string]any{
			"discovery_ingress_is_durable":           true,
			"exhausted_rows_are_not_hidden":          true,
			"backlog_does_not_become_verified_evidence": true,
			"trade_ledger_has_separate_delivery_path": true,
		},
	}
	if db == nil {
		return out, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	var oldestOpen, lastReceived sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT
			count(*) FILTER (WHERE status='pending'),
			count(*) FILTER (WHERE status='processing'),
			count(*) FILTER (WHERE status='retryable'),
			count(*) FILTER (WHERE status='exhausted'),
			count(*) FILTER (WHERE status='completed' AND processed_at >= now() - interval '24 hours'),
			min(received_at) FILTER (WHERE status IN ('pending','processing','retryable')),
			max(received_at)
		FROM pumpportal_event_inbox
	`).Scan(
		&out.PendingCount, &out.ProcessingCount, &out.RetryableCount,
		&out.ExhaustedCount, &out.Completed24hCount, &oldestOpen, &lastReceived,
	)
	if err != nil {
		if isUndefinedTableError(err) {
			return out, nil
		}
		return PumpPortalInboxHealth{}, err
	}
	out.Available = true
	out.OpenCount = out.PendingCount + out.ProcessingCount + out.RetryableCount
	if oldestOpen.Valid {
		value := oldestOpen.Time.UTC()
		out.OldestOpenAt = &value
		age := now.Sub(value)
		if age > 0 {
			out.OldestOpenAgeSeconds = int64(age.Seconds())
		}
	}
	if lastReceived.Valid {
		value := lastReceived.Time.UTC()
		out.LastReceivedAt = &value
	}
	out.Status = classifyPumpPortalInboxHealth(out)
	return out, nil
}

func classifyPumpPortalInboxHealth(health PumpPortalInboxHealth) string {
	if !health.Available {
		return "unavailable"
	}
	if health.ExhaustedCount > 0 {
		return "degraded"
	}
	if health.OpenCount >= 1000 || health.OldestOpenAgeSeconds >= 300 {
		return "backlogged"
	}
	if health.RetryableCount > 0 || health.OldestOpenAgeSeconds >= 60 {
		return "recovering"
	}
	return "healthy"
}

func pumpPortalInboxHealthIsHealthy(status string) bool {
	return strings.EqualFold(strings.TrimSpace(status), "healthy")
}
