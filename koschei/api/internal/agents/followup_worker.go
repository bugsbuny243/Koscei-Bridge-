package agents

import (
	"context"
	"database/sql"
	"fmt"
	"strings"
	"sync"
	"time"
)

type followupItem struct {
	ID         int64
	TenantID   string
	Channel    string
	ExternalID string
	Body       string
	Attempts   int
}

var followupWorkerOnce sync.Once

func (s *Service) StartFollowupWorker() {
	if s.db == nil {
		return
	}
	followupWorkerOnce.Do(func() {
		go func() {
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				s.deliverOneFollowup(context.Background())
				<-ticker.C
			}
		}()
	})
}

func (s *Service) deliverOneFollowup(ctx context.Context) {
	item, ok := s.claimFollowup(ctx)
	if !ok {
		return
	}

	if item.Channel == string(ChannelWhatsApp) {
		var lastInbound time.Time
		err := s.db.QueryRowContext(ctx, `
SELECT COALESCE(MAX(created_at), to_timestamp(0))
FROM tradepi_agent_messages
WHERE tenant_id=$1 AND channel='whatsapp' AND channel_user_id=$2 AND direction='inbound'`, item.TenantID, item.ExternalID).Scan(&lastInbound)
		if err != nil || time.Since(lastInbound) > 23*time.Hour {
			_, _ = s.db.ExecContext(ctx, `UPDATE tradepi_agent_followups SET status='cancelled', last_error='whatsapp template required outside service window', updated_at=NOW() WHERE id=$1`, item.ID)
			return
		}
	}

	var err error
	switch item.Channel {
	case string(ChannelWhatsApp):
		if !WhatsAppOutboundEnabled() {
			returnFollowupToPending(s.db, ctx, item, "whatsapp outbound not configured")
			return
		}
		err = SendWhatsAppText(ctx, item.ExternalID, item.Body)
	case string(ChannelTelegram):
		err = SendTelegramText(ctx, item.ExternalID, item.Body)
	default:
		_, _ = s.db.ExecContext(ctx, `UPDATE tradepi_agent_followups SET status='cancelled', last_error='unsupported automated followup channel', updated_at=NOW() WHERE id=$1`, item.ID)
		return
	}
	if err != nil {
		returnFollowupToPending(s.db, ctx, item, err.Error())
		return
	}
	_, _ = s.db.ExecContext(ctx, `UPDATE tradepi_agent_followups SET status='sent', sent_at=NOW(), updated_at=NOW(), last_error='' WHERE id=$1`, item.ID)
	_, _ = s.db.ExecContext(ctx, `INSERT INTO tradepi_agent_messages (tenant_id,channel,channel_user_id,direction,body,created_at) VALUES ($1,$2,$3,'outbound',$4,NOW())`, item.TenantID, item.Channel, item.ExternalID, item.Body)
}

func (s *Service) claimFollowup(ctx context.Context) (followupItem, bool) {
	var item followupItem
	err := s.db.QueryRowContext(ctx, `
UPDATE tradepi_agent_followups
SET attempts=attempts+1, updated_at=NOW()
WHERE id=(
    SELECT id FROM tradepi_agent_followups
    WHERE status='pending' AND due_at<=NOW()
    ORDER BY due_at ASC, id ASC
    FOR UPDATE SKIP LOCKED
    LIMIT 1
)
RETURNING id, tenant_id, channel, external_id, body, attempts`).Scan(&item.ID, &item.TenantID, &item.Channel, &item.ExternalID, &item.Body, &item.Attempts)
	return item, err == nil
}

func returnFollowupToPending(db *sql.DB, ctx context.Context, item followupItem, reason string) {
	reason = strings.TrimSpace(reason)
	if len(reason) > 500 {
		reason = reason[:500]
	}
	if item.Attempts >= 5 {
		_, _ = db.ExecContext(ctx, `UPDATE tradepi_agent_followups SET status='failed', last_error=$2, updated_at=NOW() WHERE id=$1`, item.ID, reason)
		return
	}
	seconds := 1 << minInt(item.Attempts, 8)
	if seconds < 30 {
		seconds = 30
	}
	if seconds > 900 {
		seconds = 900
	}
	_, _ = db.ExecContext(ctx, `UPDATE tradepi_agent_followups SET due_at=NOW()+($2*INTERVAL '1 second'), last_error=$3, updated_at=NOW() WHERE id=$1`, item.ID, seconds, fmt.Sprintf("%s", reason))
}
