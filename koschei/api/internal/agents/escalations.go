package agents

import (
	"context"
	"strings"
	"sync"
	"time"
)

type AdminEscalation struct {
	ID             int64      `json:"id"`
	TenantID       string     `json:"tenant_id"`
	Channel        string     `json:"channel"`
	ExternalID     string     `json:"external_id"`
	DisplayName    string     `json:"display_name"`
	Score          int        `json:"score"`
	Kind           string     `json:"kind"`
	Reason         string     `json:"reason"`
	Status         string     `json:"status"`
	CreatedAt      time.Time  `json:"created_at"`
	AcknowledgedAt *time.Time `json:"acknowledged_at,omitempty"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
}

var escalationWorkerOnce sync.Once

func (s *Service) StartEscalationWorker() {
	if s.db == nil {
		return
	}
	escalationWorkerOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				s.detectMissedLeads(context.Background())
				<-ticker.C
			}
		}()
	})
}

func (s *Service) detectMissedLeads(ctx context.Context) {
	// Qualified leads score >=60 that have remained unassigned for 10 minutes
	// become operator-attention events. A tenant/channel/external_id dedupe key
	// ensures the same missed lead cannot create alert spam.
	_, _ = s.db.ExecContext(ctx, `
INSERT INTO tradepi_agent_escalations (
    tenant_id, channel, external_id, kind, reason, status, dedupe_key, created_at
)
SELECT
    tenant_id,
    channel,
    external_id,
    'missed_hot_lead',
    'Qualified lead has remained unassigned for at least 10 minutes',
    'open',
    'missed-hot-lead:' || channel || ':' || external_id,
    NOW()
FROM tradepi_agent_leads
WHERE stage='qualified'
  AND score>=60
  AND COALESCE(owner_id,'')=''
  AND updated_at <= NOW() - INTERVAL '10 minutes'
ON CONFLICT (tenant_id, dedupe_key) DO NOTHING`)
}

func (s *Service) AdminEscalations(ctx context.Context, tenantID, status string, limit int) ([]AdminEscalation, error) {
	if s.db == nil {
		return nil, ErrPersistenceUnavailable
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		status = "open"
	}
	if status != "open" && status != "acknowledged" && status != "resolved" {
		return nil, ErrInvalidAdminTransition
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT e.id, e.tenant_id, e.channel, e.external_id,
       COALESCE(l.display_name,''), COALESCE(l.score,0),
       e.kind, e.reason, e.status, e.created_at, e.acknowledged_at, e.resolved_at
FROM tradepi_agent_escalations e
LEFT JOIN tradepi_agent_leads l
  ON l.tenant_id=e.tenant_id AND l.channel=e.channel AND l.external_id=e.external_id
WHERE e.tenant_id=$1 AND e.status=$2
ORDER BY e.created_at ASC
LIMIT $3`, strings.TrimSpace(tenantID), status, adminLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AdminEscalation, 0)
	for rows.Next() {
		var item AdminEscalation
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Channel, &item.ExternalID, &item.DisplayName, &item.Score, &item.Kind, &item.Reason, &item.Status, &item.CreatedAt, &item.AcknowledgedAt, &item.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Service) AdminUpdateEscalation(ctx context.Context, tenantID string, id int64, status string) error {
	if s.db == nil {
		return ErrPersistenceUnavailable
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "acknowledged" && status != "resolved" {
		return ErrInvalidAdminTransition
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE tradepi_agent_escalations
SET status=$3,
    acknowledged_at=CASE WHEN $3='acknowledged' AND acknowledged_at IS NULL THEN NOW() ELSE acknowledged_at END,
    resolved_at=CASE WHEN $3='resolved' THEN NOW() ELSE resolved_at END
WHERE id=$1 AND tenant_id=$2 AND status IN ('open','acknowledged')`, id, strings.TrimSpace(tenantID), status)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return ErrAdminRecordNotFound
	}
	return nil
}
