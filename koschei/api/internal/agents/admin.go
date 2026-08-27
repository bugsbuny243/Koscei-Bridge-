package agents

import (
	"context"
	"errors"
	"time"
)

var ErrPersistenceUnavailable = errors.New("agent persistence unavailable")

type AdminLead struct {
	TenantID      string    `json:"tenant_id"`
	Channel       string    `json:"channel"`
	ExternalID    string    `json:"external_id"`
	DisplayName   string    `json:"display_name"`
	Stage         string    `json:"stage"`
	Score         int       `json:"score"`
	BudgetKnown   bool      `json:"budget_known"`
	ModelKnown    bool      `json:"model_known"`
	LocationKnown bool      `json:"location_known"`
	TradeInKnown  bool      `json:"trade_in_known"`
	UpdatedAt     time.Time `json:"updated_at"`
}

type AdminHandoff struct {
	ID          int64      `json:"id"`
	TenantID    string     `json:"tenant_id"`
	Channel     string     `json:"channel"`
	ExternalID  string     `json:"external_id"`
	DisplayName string     `json:"display_name"`
	Reason      string     `json:"reason"`
	Status      string     `json:"status"`
	RequestedAt time.Time  `json:"requested_at"`
	ResolvedAt  *time.Time `json:"resolved_at,omitempty"`
}

type AdminAppointment struct {
	ID           int64      `json:"id"`
	TenantID     string     `json:"tenant_id"`
	Channel      string     `json:"channel"`
	ExternalID   string     `json:"external_id"`
	DisplayName  string     `json:"display_name"`
	RequestText  string     `json:"request_text"`
	Status       string     `json:"status"`
	ScheduledFor *time.Time `json:"scheduled_for,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type AdminQueue struct {
	TenantID     string             `json:"tenant_id"`
	Leads        []AdminLead        `json:"leads"`
	Handoffs     []AdminHandoff     `json:"handoffs"`
	Appointments []AdminAppointment `json:"appointments"`
}

func adminLimit(limit int) int {
	if limit <= 0 {
		return 25
	}
	if limit > 100 {
		return 100
	}
	return limit
}

func (s *Service) AdminLeads(ctx context.Context, tenantID string, limit int) ([]AdminLead, error) {
	if s.db == nil {
		return nil, ErrPersistenceUnavailable
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT tenant_id, channel, external_id, display_name, stage, score,
       budget_known, model_known, location_known, trade_in_known, updated_at
FROM tradepi_agent_leads
WHERE tenant_id=$1
ORDER BY score DESC, updated_at DESC
LIMIT $2`, tenantID, adminLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AdminLead, 0)
	for rows.Next() {
		var item AdminLead
		if err := rows.Scan(
			&item.TenantID, &item.Channel, &item.ExternalID, &item.DisplayName, &item.Stage, &item.Score,
			&item.BudgetKnown, &item.ModelKnown, &item.LocationKnown, &item.TradeInKnown, &item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Service) AdminHandoffs(ctx context.Context, tenantID, status string, limit int) ([]AdminHandoff, error) {
	if s.db == nil {
		return nil, ErrPersistenceUnavailable
	}
	if status == "" {
		status = "requested"
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT h.id, h.tenant_id, h.channel, h.external_id, COALESCE(l.display_name,''),
       h.reason, h.status, h.requested_at, h.resolved_at
FROM tradepi_agent_handoffs h
LEFT JOIN tradepi_agent_leads l
  ON l.tenant_id=h.tenant_id AND l.channel=h.channel AND l.external_id=h.external_id
WHERE h.tenant_id=$1 AND h.status=$2
ORDER BY h.requested_at ASC
LIMIT $3`, tenantID, status, adminLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AdminHandoff, 0)
	for rows.Next() {
		var item AdminHandoff
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Channel, &item.ExternalID, &item.DisplayName, &item.Reason, &item.Status, &item.RequestedAt, &item.ResolvedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Service) AdminAppointments(ctx context.Context, tenantID, status string, limit int) ([]AdminAppointment, error) {
	if s.db == nil {
		return nil, ErrPersistenceUnavailable
	}
	if status == "" {
		status = "requested"
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT a.id, a.tenant_id, a.channel, a.external_id, COALESCE(l.display_name,''),
       a.request_text, a.status, a.scheduled_for, a.created_at, a.updated_at
FROM tradepi_agent_appointment_requests a
LEFT JOIN tradepi_agent_leads l
  ON l.tenant_id=a.tenant_id AND l.channel=a.channel AND l.external_id=a.external_id
WHERE a.tenant_id=$1 AND a.status=$2
ORDER BY a.created_at ASC
LIMIT $3`, tenantID, status, adminLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AdminAppointment, 0)
	for rows.Next() {
		var item AdminAppointment
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Channel, &item.ExternalID, &item.DisplayName, &item.RequestText, &item.Status, &item.ScheduledFor, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Service) AdminQueue(ctx context.Context, tenantID string, limit int) (AdminQueue, error) {
	leads, err := s.AdminLeads(ctx, tenantID, limit)
	if err != nil {
		return AdminQueue{}, err
	}
	handoffs, err := s.AdminHandoffs(ctx, tenantID, "requested", limit)
	if err != nil {
		return AdminQueue{}, err
	}
	appointments, err := s.AdminAppointments(ctx, tenantID, "requested", limit)
	if err != nil {
		return AdminQueue{}, err
	}
	return AdminQueue{TenantID: tenantID, Leads: leads, Handoffs: handoffs, Appointments: appointments}, nil
}
