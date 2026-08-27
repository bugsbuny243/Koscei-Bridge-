package agents

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"sync"
	"time"

	_ "github.com/lib/pq"
)

type DemoInventory struct{ vehicles []Vehicle }

func NewDemoInventory() *DemoInventory {
	return &DemoInventory{vehicles: []Vehicle{
		{ID: "demo-bmw-320i", Make: "BMW", Model: "320i", Year: 2025, PriceTRY: 2450000, City: "Istanbul", InStock: true},
		{ID: "demo-bmw-520i", Make: "BMW", Model: "520i", Year: 2024, PriceTRY: 3650000, City: "Istanbul", InStock: true},
		{ID: "demo-mercedes-c200", Make: "Mercedes-Benz", Model: "C200", Year: 2025, PriceTRY: 3350000, City: "Ankara", InStock: true},
	}}
}

func (d *DemoInventory) Search(_ context.Context, query string) ([]Vehicle, error) {
	q := strings.ToLower(strings.TrimSpace(query))
	out := make([]Vehicle, 0)
	for _, vehicle := range d.vehicles {
		haystack := strings.ToLower(vehicle.Make + " " + vehicle.Model + " " + vehicle.City)
		if vehicle.InStock && (q == "" || strings.Contains(haystack, q) || strings.Contains(q, strings.ToLower(vehicle.Model))) {
			out = append(out, vehicle)
		}
	}
	return out, nil
}

type Service struct {
	mu    sync.RWMutex
	leads map[string]Lead
	core  *Core
	db    *sql.DB
	llm   *LLMClient
}

func NewService() *Service {
	s := &Service{leads: map[string]Lead{}, core: NewCore(NewDemoInventory()), llm: NewLLMClientFromEnv()}
	if dsn := strings.TrimSpace(os.Getenv("DATABASE_URL")); dsn != "" {
		if db, err := sql.Open("postgres", dsn); err == nil {
			db.SetMaxOpenConns(2)
			db.SetMaxIdleConns(0)
			db.SetConnMaxLifetime(5 * time.Minute)
			s.db = db
		}
	}
	return s
}

func (s *Service) PersistenceEnabled() bool { return s.db != nil }
func (s *Service) LLMEnabled() bool { return s.llm != nil && s.llm.Enabled() }

func (s *Service) PersistenceReady(ctx context.Context) bool {
	if s.db == nil {
		return false
	}
	var leads, messages bool
	if err := s.db.QueryRowContext(ctx, `SELECT to_regclass('public.tradepi_agent_leads') IS NOT NULL`).Scan(&leads); err != nil {
		return false
	}
	if err := s.db.QueryRowContext(ctx, `SELECT to_regclass('public.tradepi_agent_messages') IS NOT NULL`).Scan(&messages); err != nil {
		return false
	}
	return leads && messages
}

func (s *Service) Handle(ctx context.Context, msg Message) Result {
	key := msg.TenantID + ":" + string(msg.Channel) + ":" + msg.ChannelUserID
	current, ok := s.loadLead(ctx, msg)
	if !ok {
		s.mu.RLock()
		current = s.leads[key]
		s.mu.RUnlock()
	}

	result := s.core.Handle(ctx, msg, current)
	if s.llm != nil && s.llm.Enabled() {
		if reply, err := s.llm.Rewrite(ctx, msg.Text, result.Reply, result.Lead, result.Vehicles); err == nil && strings.TrimSpace(reply) != "" {
			result.Reply = reply
		}
	}

	s.mu.Lock()
	s.leads[key] = result.Lead
	s.mu.Unlock()

	if s.db != nil {
		_ = s.saveInbound(ctx, msg)
		_ = s.saveLead(ctx, msg, result.Lead)
	}
	return result
}

func (s *Service) RecordOutbound(ctx context.Context, msg Message, body string) {
	if s.db == nil || strings.TrimSpace(body) == "" {
		return
	}
	_, _ = s.db.ExecContext(ctx, `
INSERT INTO tradepi_agent_messages (tenant_id, channel, channel_chat_id, channel_user_id, direction, body, created_at)
VALUES ($1,$2,$3,$4,'outbound',$5,NOW())`, msg.TenantID, string(msg.Channel), msg.ChannelChatID, msg.ChannelUserID, body)
}

func (s *Service) loadLead(ctx context.Context, msg Message) (Lead, bool) {
	if s.db == nil {
		return Lead{}, false
	}
	var lead Lead
	err := s.db.QueryRowContext(ctx, `
SELECT tenant_id, external_id, display_name, stage, score,
       budget_known, model_known, location_known, trade_in_known, updated_at
FROM tradepi_agent_leads
WHERE tenant_id=$1 AND channel=$2 AND external_id=$3`, msg.TenantID, string(msg.Channel), msg.ChannelUserID).Scan(
		&lead.TenantID, &lead.ExternalID, &lead.DisplayName, &lead.Stage, &lead.Score,
		&lead.BudgetKnown, &lead.ModelKnown, &lead.LocationKnown, &lead.TradeInKnown, &lead.UpdatedAt,
	)
	return lead, err == nil
}

func (s *Service) saveLead(ctx context.Context, msg Message, lead Lead) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO tradepi_agent_leads (
 tenant_id, channel, external_id, display_name, stage, score,
 budget_known, model_known, location_known, trade_in_known, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)
ON CONFLICT (tenant_id, channel, external_id) DO UPDATE SET
 display_name=EXCLUDED.display_name,
 stage=EXCLUDED.stage,
 score=EXCLUDED.score,
 budget_known=EXCLUDED.budget_known,
 model_known=EXCLUDED.model_known,
 location_known=EXCLUDED.location_known,
 trade_in_known=EXCLUDED.trade_in_known,
 updated_at=EXCLUDED.updated_at`,
		lead.TenantID, string(msg.Channel), lead.ExternalID, lead.DisplayName, lead.Stage, lead.Score,
		lead.BudgetKnown, lead.ModelKnown, lead.LocationKnown, lead.TradeInKnown, lead.UpdatedAt,
	)
	return err
}

func (s *Service) saveInbound(ctx context.Context, msg Message) error {
	_, err := s.db.ExecContext(ctx, `
INSERT INTO tradepi_agent_messages (tenant_id, channel, channel_chat_id, channel_user_id, direction, body, created_at)
VALUES ($1,$2,$3,$4,'inbound',$5,$6)`, msg.TenantID, string(msg.Channel), msg.ChannelChatID, msg.ChannelUserID, msg.Text, msg.ReceivedAt)
	return err
}
