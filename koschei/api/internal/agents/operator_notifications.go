package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

type operatorNotificationItem struct {
	ID           int64
	TenantID     string
	EscalationID int64
	Attempts     int
	LeadChannel  string
	ExternalID   string
	DisplayName  string
	Score        int
	Reason       string
	EscalationAt time.Time
	EscalationStatus string
}

var operatorNotificationWorkerOnce sync.Once

func (s *Service) StartOperatorNotificationWorker() {
	if s.db == nil {
		return
	}
	operatorNotificationWorkerOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				s.deliverOneOperatorNotification(context.Background())
				<-ticker.C
			}
		}()
	})
}

func (s *Service) deliverOneOperatorNotification(ctx context.Context) {
	item, ok := s.claimOperatorNotification(ctx)
	if !ok {
		return
	}
	if item.EscalationStatus == "resolved" {
		_, _ = s.db.ExecContext(ctx, `
UPDATE tradepi_agent_operator_notifications
SET status='cancelled', updated_at=NOW(), last_error='escalation already resolved'
WHERE id=$1 AND status='processing'`, item.ID)
		return
	}

	mode := ""
	var err error
	if strings.TrimSpace(os.Getenv("TRADEPI_OPERATOR_WEBHOOK_URL")) != "" {
		mode = "webhook"
		err = deliverOperatorWebhook(ctx, item)
	} else if strings.TrimSpace(os.Getenv("TRADEPI_OPERATOR_TELEGRAM_CHAT_ID")) != "" {
		mode = "telegram"
		err = SendTelegramText(ctx, strings.TrimSpace(os.Getenv("TRADEPI_OPERATOR_TELEGRAM_CHAT_ID")), formatOperatorTelegramAlert(item))
	} else {
		_, _ = s.db.ExecContext(ctx, `
UPDATE tradepi_agent_operator_notifications
SET status='pending', attempts=GREATEST(attempts-1,0), next_attempt_at=NOW()+INTERVAL '5 minutes',
    updated_at=NOW(), last_error='operator notification destination not configured'
WHERE id=$1 AND status='processing'`, item.ID)
		return
	}

	if err != nil {
		s.retryOperatorNotification(ctx, item, mode+": "+err.Error())
		return
	}
	_, _ = s.db.ExecContext(ctx, `
UPDATE tradepi_agent_operator_notifications
SET status='delivered', delivered_at=NOW(), updated_at=NOW(), last_error=''
WHERE id=$1 AND status='processing'`, item.ID)
}

func (s *Service) claimOperatorNotification(ctx context.Context) (operatorNotificationItem, bool) {
	var item operatorNotificationItem
	err := s.db.QueryRowContext(ctx, `
WITH candidate AS (
    SELECT n.id
    FROM tradepi_agent_operator_notifications n
    WHERE n.status='pending' AND n.next_attempt_at<=NOW()
    ORDER BY n.next_attempt_at ASC, n.id ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
), claimed AS (
    UPDATE tradepi_agent_operator_notifications n
    SET status='processing', attempts=attempts+1, updated_at=NOW()
    FROM candidate c
    WHERE n.id=c.id
    RETURNING n.id, n.tenant_id, n.escalation_id, n.attempts
)
SELECT c.id, c.tenant_id, c.escalation_id, c.attempts,
       e.channel, e.external_id, COALESCE(l.display_name,''), COALESCE(l.score,0),
       e.reason, e.created_at, e.status
FROM claimed c
JOIN tradepi_agent_escalations e ON e.id=c.escalation_id
LEFT JOIN tradepi_agent_leads l
  ON l.tenant_id=e.tenant_id AND l.channel=e.channel AND l.external_id=e.external_id`,
	).Scan(
		&item.ID, &item.TenantID, &item.EscalationID, &item.Attempts,
		&item.LeadChannel, &item.ExternalID, &item.DisplayName, &item.Score,
		&item.Reason, &item.EscalationAt, &item.EscalationStatus,
	)
	return item, err == nil
}

func (s *Service) retryOperatorNotification(ctx context.Context, item operatorNotificationItem, reason string) {
	reason = strings.TrimSpace(reason)
	if len(reason) > 500 {
		reason = reason[:500]
	}
	if item.Attempts >= 8 {
		_, _ = s.db.ExecContext(ctx, `
UPDATE tradepi_agent_operator_notifications
SET status='failed', updated_at=NOW(), last_error=$2
WHERE id=$1 AND status='processing'`, item.ID, reason)
		return
	}
	seconds := 1 << minInt(item.Attempts, 8)
	if seconds < 30 {
		seconds = 30
	}
	if seconds > 900 {
		seconds = 900
	}
	_, _ = s.db.ExecContext(ctx, `
UPDATE tradepi_agent_operator_notifications
SET status='pending', next_attempt_at=NOW()+($2*INTERVAL '1 second'), updated_at=NOW(), last_error=$3
WHERE id=$1 AND status='processing'`, item.ID, seconds, reason)
}

func deliverOperatorWebhook(ctx context.Context, item operatorNotificationItem) error {
	endpoint := strings.TrimSpace(os.Getenv("TRADEPI_OPERATOR_WEBHOOK_URL"))
	if endpoint == "" {
		return fmt.Errorf("operator webhook not configured")
	}
	payload, err := json.Marshal(map[string]any{
		"event_type": "sales.missed_hot_lead",
		"tenant_id": item.TenantID,
		"escalation_id": item.EscalationID,
		"lead": map[string]any{
			"channel": item.LeadChannel,
			"external_id": item.ExternalID,
			"display_name": item.DisplayName,
			"score": item.Score,
		},
		"reason": item.Reason,
		"escalated_at": item.EscalationAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TradePI-Event", "sales.missed_hot_lead")
	if secret := strings.TrimSpace(os.Getenv("TRADEPI_OPERATOR_WEBHOOK_SECRET")); secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("operator webhook status %d", resp.StatusCode)
	}
	return nil
}

func formatOperatorTelegramAlert(item operatorNotificationItem) string {
	name := strings.TrimSpace(item.DisplayName)
	if name == "" {
		name = item.ExternalID
	}
	return fmt.Sprintf(
		"🔥 TradePI hot lead needs attention\nLead: %s\nScore: %d\nChannel: %s\nID: %s\nReason: %s",
		name, item.Score, item.LeadChannel, item.ExternalID, item.Reason,
	)
}
