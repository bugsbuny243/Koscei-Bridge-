package agents

import (
	"context"
	"strings"
	"time"
)

type AdminFollowup struct {
	ID         int64      `json:"id"`
	TenantID   string     `json:"tenant_id"`
	Channel    string     `json:"channel"`
	ExternalID string     `json:"external_id"`
	DisplayName string    `json:"display_name"`
	Kind       string     `json:"kind"`
	Body       string     `json:"body"`
	Status     string     `json:"status"`
	DueAt      time.Time  `json:"due_at"`
	Attempts   int        `json:"attempts"`
	LastError  string     `json:"last_error"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	SentAt     *time.Time `json:"sent_at,omitempty"`
}

func (s *Service) AdminFollowups(ctx context.Context, tenantID, status string, limit int) ([]AdminFollowup, error) {
	if s.db == nil {
		return nil, ErrPersistenceUnavailable
	}
	tenantID = strings.TrimSpace(tenantID)
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		status = "pending"
	}
	if status != "pending" && status != "processing" && status != "sent" && status != "cancelled" && status != "failed" {
		return nil, ErrInvalidAdminTransition
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT f.id, f.tenant_id, f.channel, f.external_id, COALESCE(l.display_name,''),
       f.kind, f.body, f.status, f.due_at, f.attempts, f.last_error,
       f.created_at, f.updated_at, f.sent_at
FROM tradepi_agent_followups f
LEFT JOIN tradepi_agent_leads l
  ON l.tenant_id=f.tenant_id AND l.channel=f.channel AND l.external_id=f.external_id
WHERE f.tenant_id=$1 AND f.status=$2
ORDER BY CASE WHEN f.status='pending' THEN f.due_at END ASC, f.updated_at DESC, f.id DESC
LIMIT $3`, tenantID, status, adminLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	items := make([]AdminFollowup, 0)
	for rows.Next() {
		var item AdminFollowup
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Channel, &item.ExternalID, &item.DisplayName,
			&item.Kind, &item.Body, &item.Status, &item.DueAt, &item.Attempts, &item.LastError,
			&item.CreatedAt, &item.UpdatedAt, &item.SentAt); err != nil {
			return nil, err
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func (s *Service) AdminCancelFollowup(ctx context.Context, tenantID string, id int64) error {
	if s.db == nil {
		return ErrPersistenceUnavailable
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE tradepi_agent_followups
SET status='cancelled', updated_at=NOW(), last_error=CASE WHEN last_error='' THEN 'cancelled by operator' ELSE last_error END
WHERE id=$1 AND tenant_id=$2 AND status IN ('pending','failed')`, id, strings.TrimSpace(tenantID))
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

func (s *Service) AdminRetryFollowup(ctx context.Context, tenantID string, id int64) error {
	if s.db == nil {
		return ErrPersistenceUnavailable
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE tradepi_agent_followups
SET status='pending', due_at=NOW(), attempts=0, last_error='', updated_at=NOW()
WHERE id=$1 AND tenant_id=$2 AND status='failed'`, id, strings.TrimSpace(tenantID))
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
