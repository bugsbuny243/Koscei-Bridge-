package agents

import (
	"context"
	"os"
	"strings"
)

type AdminEscalationMetrics struct {
	Open                 int64   `json:"open"`
	Acknowledged         int64   `json:"acknowledged"`
	ResolvedLast24Hours  int64   `json:"resolved_last_24_hours"`
	OldestOpenSeconds    int64   `json:"oldest_open_seconds"`
	AvgAcknowledgeSeconds float64 `json:"avg_acknowledge_seconds"`
	NotificationMode     string  `json:"notification_mode"`
}

func (s *Service) AdminEscalationMetrics(ctx context.Context, tenantID string) (AdminEscalationMetrics, error) {
	if s.db == nil {
		return AdminEscalationMetrics{}, ErrPersistenceUnavailable
	}
	var out AdminEscalationMetrics
	err := s.db.QueryRowContext(ctx, `
SELECT
    COUNT(*) FILTER (WHERE status='open'),
    COUNT(*) FILTER (WHERE status='acknowledged'),
    COUNT(*) FILTER (WHERE status='resolved' AND resolved_at >= NOW()-INTERVAL '24 hours'),
    COALESCE(EXTRACT(EPOCH FROM (NOW()-MIN(created_at) FILTER (WHERE status='open'))),0)::bigint,
    COALESCE(AVG(EXTRACT(EPOCH FROM (acknowledged_at-created_at))) FILTER (WHERE acknowledged_at IS NOT NULL),0)::double precision
FROM tradepi_agent_escalations
WHERE tenant_id=$1`, strings.TrimSpace(tenantID)).Scan(
		&out.Open,
		&out.Acknowledged,
		&out.ResolvedLast24Hours,
		&out.OldestOpenSeconds,
		&out.AvgAcknowledgeSeconds,
	)
	if err != nil {
		return AdminEscalationMetrics{}, err
	}
	out.NotificationMode = operatorNotificationMode()
	return out, nil
}

func operatorNotificationMode() string {
	if strings.TrimSpace(os.Getenv("TRADEPI_OPERATOR_WEBHOOK_URL")) != "" {
		return "webhook"
	}
	if strings.TrimSpace(os.Getenv("TRADEPI_OPERATOR_TELEGRAM_CHAT_ID")) != "" && strings.TrimSpace(os.Getenv("TELEGRAM_BOT_TOKEN")) != "" {
		return "telegram"
	}
	return "not_configured"
}
