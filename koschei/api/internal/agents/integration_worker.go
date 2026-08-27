package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

type integrationOutboxItem struct {
	ID        int64
	TenantID  string
	EventType string
	Payload   json.RawMessage
	Attempts  int
}

func (s *Service) IntegrationEnabled() bool {
	return s.db != nil && strings.TrimSpace(os.Getenv("TRADEPI_CALENDAR_WEBHOOK_URL")) != ""
}

func (s *Service) startIntegrationWorker() {
	if !s.IntegrationEnabled() {
		return
	}
	go func() {
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()
		for {
			s.deliverOneIntegration(context.Background())
			<-ticker.C
		}
	}()
}

func (s *Service) deliverOneIntegration(ctx context.Context) {
	item, ok := s.claimIntegration(ctx)
	if !ok {
		return
	}
	if err := deliverIntegrationWebhook(ctx, item); err != nil {
		backoffSeconds := 1 << minInt(item.Attempts, 8)
		if backoffSeconds > 300 {
			backoffSeconds = 300
		}
		message := err.Error()
		if len(message) > 500 {
			message = message[:500]
		}
		_, _ = s.db.ExecContext(ctx, `
UPDATE tradepi_agent_integration_outbox
SET status='pending', next_attempt_at=NOW()+($2*INTERVAL '1 second'), last_error=$3
WHERE id=$1 AND status='processing'`, item.ID, backoffSeconds, message)
		return
	}
	_, _ = s.db.ExecContext(ctx, `
UPDATE tradepi_agent_integration_outbox
SET status='delivered', delivered_at=NOW(), last_error=''
WHERE id=$1 AND status='processing'`, item.ID)
}

func (s *Service) claimIntegration(ctx context.Context) (integrationOutboxItem, bool) {
	var item integrationOutboxItem
	err := s.db.QueryRowContext(ctx, `
UPDATE tradepi_agent_integration_outbox
SET status='processing', attempts=attempts+1
WHERE id=(
    SELECT id FROM tradepi_agent_integration_outbox
    WHERE status='pending' AND next_attempt_at<=NOW()
    ORDER BY next_attempt_at ASC, id ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING id, tenant_id, event_type, payload, attempts`).Scan(
		&item.ID, &item.TenantID, &item.EventType, &item.Payload, &item.Attempts,
	)
	return item, err == nil
}

func deliverIntegrationWebhook(ctx context.Context, item integrationOutboxItem) error {
	endpoint := strings.TrimSpace(os.Getenv("TRADEPI_CALENDAR_WEBHOOK_URL"))
	if endpoint == "" {
		return fmt.Errorf("calendar webhook not configured")
	}
	body, err := json.Marshal(map[string]any{
		"event_type": item.EventType,
		"tenant_id":  item.TenantID,
		"event_id":   item.ID,
		"payload":    item.Payload,
	})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-TradePI-Event", item.EventType)
	if secret := strings.TrimSpace(os.Getenv("TRADEPI_CALENDAR_WEBHOOK_SECRET")); secret != "" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("calendar webhook status %d", resp.StatusCode)
	}
	return nil
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
