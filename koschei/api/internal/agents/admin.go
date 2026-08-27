package agents

import (
	"context"
	"errors"
	"strings"
	"time"
)

var ErrPersistenceUnavailable = errors.New("agent persistence unavailable")
var ErrAdminRecordNotFound = errors.New("agent admin record not found")
var ErrInvalidAdminTransition = errors.New("invalid agent admin transition")

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
	OwnerID       string    `json:"owner_id"`
	CRMStatus     string    `json:"crm_status"`
	CRMExternalID string    `json:"crm_external_id"`
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
	ID               int64      `json:"id"`
	TenantID         string     `json:"tenant_id"`
	Channel          string     `json:"channel"`
	ExternalID       string     `json:"external_id"`
	DisplayName      string     `json:"display_name"`
	RequestText      string     `json:"request_text"`
	Status           string     `json:"status"`
	ScheduledFor     *time.Time `json:"scheduled_for,omitempty"`
	CalendarProvider string     `json:"calendar_provider"`
	CalendarEventID  string     `json:"calendar_event_id"`
	CreatedAt        time.Time  `json:"created_at"`
	UpdatedAt        time.Time  `json:"updated_at"`
}

type AdminRevenueEvent struct {
	ID          int64     `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Channel     string    `json:"channel"`
	ExternalID  string    `json:"external_id"`
	AmountMinor int64     `json:"amount_minor"`
	Currency    string    `json:"currency"`
	Source      string    `json:"source"`
	EvidenceRef string    `json:"evidence_ref"`
	Status      string    `json:"status"`
	OccurredAt  time.Time `json:"occurred_at"`
	CreatedAt   time.Time `json:"created_at"`
}

type AdminRevenueTotal struct {
	Currency    string `json:"currency"`
	AmountMinor int64  `json:"amount_minor"`
	Sales       int64  `json:"sales"`
}

type AdminRevenueSummary struct {
	Totals []AdminRevenueTotal `json:"totals"`
}

type AdminQueue struct {
	TenantID     string              `json:"tenant_id"`
	Leads        []AdminLead         `json:"leads"`
	Handoffs     []AdminHandoff      `json:"handoffs"`
	Appointments []AdminAppointment  `json:"appointments"`
	Revenue      AdminRevenueSummary `json:"revenue"`
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
       budget_known, model_known, location_known, trade_in_known,
       owner_id, crm_status, crm_external_id, updated_at
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
			&item.BudgetKnown, &item.ModelKnown, &item.LocationKnown, &item.TradeInKnown,
			&item.OwnerID, &item.CRMStatus, &item.CRMExternalID, &item.UpdatedAt,
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
       a.request_text, a.status, a.scheduled_for, a.calendar_provider, a.calendar_event_id,
       a.created_at, a.updated_at
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
		if err := rows.Scan(
			&item.ID, &item.TenantID, &item.Channel, &item.ExternalID, &item.DisplayName,
			&item.RequestText, &item.Status, &item.ScheduledFor, &item.CalendarProvider, &item.CalendarEventID,
			&item.CreatedAt, &item.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Service) AdminRevenueSummary(ctx context.Context, tenantID string) (AdminRevenueSummary, error) {
	if s.db == nil {
		return AdminRevenueSummary{}, ErrPersistenceUnavailable
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT currency, COALESCE(SUM(amount_minor),0), COUNT(*)
FROM tradepi_agent_revenue_events
WHERE tenant_id=$1 AND status='verified'
GROUP BY currency
ORDER BY currency`, tenantID)
	if err != nil {
		return AdminRevenueSummary{}, err
	}
	defer rows.Close()
	out := AdminRevenueSummary{Totals: make([]AdminRevenueTotal, 0)}
	for rows.Next() {
		var item AdminRevenueTotal
		if err := rows.Scan(&item.Currency, &item.AmountMinor, &item.Sales); err != nil {
			return AdminRevenueSummary{}, err
		}
		out.Totals = append(out.Totals, item)
	}
	return out, rows.Err()
}

func (s *Service) AdminRevenueEvents(ctx context.Context, tenantID string, limit int) ([]AdminRevenueEvent, error) {
	if s.db == nil {
		return nil, ErrPersistenceUnavailable
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, tenant_id, channel, external_id, amount_minor, currency, source, evidence_ref, status, occurred_at, created_at
FROM tradepi_agent_revenue_events
WHERE tenant_id=$1
ORDER BY occurred_at DESC, id DESC
LIMIT $2`, tenantID, adminLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AdminRevenueEvent, 0)
	for rows.Next() {
		var item AdminRevenueEvent
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Channel, &item.ExternalID, &item.AmountMinor, &item.Currency, &item.Source, &item.EvidenceRef, &item.Status, &item.OccurredAt, &item.CreatedAt); err != nil {
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
	revenue, err := s.AdminRevenueSummary(ctx, tenantID)
	if err != nil {
		return AdminQueue{}, err
	}
	return AdminQueue{TenantID: tenantID, Leads: leads, Handoffs: handoffs, Appointments: appointments, Revenue: revenue}, nil
}

func (s *Service) AdminAssignLead(ctx context.Context, tenantID, channel, externalID, ownerID, crmExternalID string) error {
	if s.db == nil {
		return ErrPersistenceUnavailable
	}
	ownerID = strings.TrimSpace(ownerID)
	if ownerID == "" {
		return ErrInvalidAdminTransition
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE tradepi_agent_leads
SET owner_id=$4,
    crm_status='assigned',
    crm_external_id=CASE WHEN $5<>'' THEN $5 ELSE crm_external_id END,
    updated_at=NOW()
WHERE tenant_id=$1 AND channel=$2 AND external_id=$3`, tenantID, channel, externalID, ownerID, strings.TrimSpace(crmExternalID))
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

func (s *Service) AdminResolveHandoff(ctx context.Context, tenantID string, id int64) error {
	if s.db == nil {
		return ErrPersistenceUnavailable
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE tradepi_agent_handoffs
SET status='resolved', resolved_at=NOW()
WHERE id=$1 AND tenant_id=$2 AND status='requested'`, id, tenantID)
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

func (s *Service) AdminUpdateAppointment(ctx context.Context, tenantID string, id int64, status string, scheduledFor *time.Time) error {
	return s.AdminUpdateAppointmentCalendar(ctx, tenantID, id, status, scheduledFor, "", "")
}

func (s *Service) AdminUpdateAppointmentCalendar(ctx context.Context, tenantID string, id int64, status string, scheduledFor *time.Time, provider, eventID string) error {
	if s.db == nil {
		return ErrPersistenceUnavailable
	}
	if status != "confirmed" && status != "cancelled" {
		return ErrInvalidAdminTransition
	}
	if status == "confirmed" && (scheduledFor == nil || scheduledFor.IsZero()) {
		return ErrInvalidAdminTransition
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE tradepi_agent_appointment_requests
SET status=$3,
    scheduled_for=CASE WHEN $3='confirmed' THEN $4 ELSE scheduled_for END,
    calendar_provider=CASE WHEN $3='confirmed' THEN $5 ELSE calendar_provider END,
    calendar_event_id=CASE WHEN $3='confirmed' THEN $6 ELSE calendar_event_id END,
    updated_at=NOW()
WHERE id=$1 AND tenant_id=$2 AND status='requested'`, id, tenantID, status, scheduledFor, strings.TrimSpace(provider), strings.TrimSpace(eventID))
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

func (s *Service) AdminRecordRevenue(ctx context.Context, event AdminRevenueEvent) error {
	if s.db == nil {
		return ErrPersistenceUnavailable
	}
	event.TenantID = strings.TrimSpace(event.TenantID)
	event.Channel = strings.TrimSpace(event.Channel)
	event.ExternalID = strings.TrimSpace(event.ExternalID)
	event.Currency = strings.ToUpper(strings.TrimSpace(event.Currency))
	event.Source = strings.TrimSpace(event.Source)
	event.EvidenceRef = strings.TrimSpace(event.EvidenceRef)
	if event.TenantID == "" || event.Channel == "" || event.ExternalID == "" || event.AmountMinor <= 0 || event.Currency == "" || event.Source == "" || event.EvidenceRef == "" || event.OccurredAt.IsZero() {
		return ErrInvalidAdminTransition
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO tradepi_agent_revenue_events (
 tenant_id, channel, external_id, amount_minor, currency, source, evidence_ref, status, occurred_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,'verified',$8)`,
		event.TenantID, event.Channel, event.ExternalID, event.AmountMinor, event.Currency, event.Source, event.EvidenceRef, event.OccurredAt,
	)
	return err
}
