package agents

import (
	"context"
	"net/mail"
	"net/url"
	"strings"
	"time"
)

type PilotLead struct {
	ID              int64     `json:"id"`
	BusinessName    string    `json:"business_name"`
	ContactName     string    `json:"contact_name"`
	Email           string    `json:"email"`
	Phone           string    `json:"phone"`
	Website         string    `json:"website"`
	Vertical        string    `json:"vertical"`
	MonthlyLeadBand string    `json:"monthly_lead_band"`
	Message         string    `json:"message"`
	Status          string    `json:"status"`
	Source          string    `json:"source"`
	CreatedAt       time.Time `json:"created_at"`
	UpdatedAt       time.Time `json:"updated_at"`
}

func (s *Service) SubmitPilotLead(ctx context.Context, lead PilotLead) error {
	if s.db == nil {
		return ErrPersistenceUnavailable
	}
	lead.BusinessName = strings.TrimSpace(lead.BusinessName)
	lead.ContactName = strings.TrimSpace(lead.ContactName)
	lead.Email = strings.ToLower(strings.TrimSpace(lead.Email))
	lead.Phone = strings.TrimSpace(lead.Phone)
	lead.Website = strings.TrimRight(strings.TrimSpace(lead.Website), "/")
	lead.Vertical = strings.ToLower(strings.TrimSpace(lead.Vertical))
	lead.MonthlyLeadBand = strings.ToLower(strings.TrimSpace(lead.MonthlyLeadBand))
	lead.Message = strings.TrimSpace(lead.Message)
	lead.Source = strings.TrimSpace(lead.Source)
	if lead.Vertical == "" {
		lead.Vertical = "general"
	}
	if lead.MonthlyLeadBand == "" {
		lead.MonthlyLeadBand = "unknown"
	}
	if lead.Source == "" {
		lead.Source = "agents-page"
	}
	if !validPilotLead(lead) {
		return ErrInvalidAdminTransition
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO tradepi_agent_pilot_leads (
    business_name, contact_name, email, phone, website, vertical,
    monthly_lead_band, message, status, source, created_at, updated_at
)
SELECT $1,$2,$3,$4,$5,$6,$7,$8,'new',$9,NOW(),NOW()
WHERE NOT EXISTS (
    SELECT 1 FROM tradepi_agent_pilot_leads
    WHERE LOWER(email)=LOWER($3) AND website=$5 AND created_at > NOW()-INTERVAL '24 hours'
)`, lead.BusinessName, lead.ContactName, lead.Email, lead.Phone, lead.Website, lead.Vertical, lead.MonthlyLeadBand, lead.Message, lead.Source)
	return err
}

func (s *Service) AdminPilotLeads(ctx context.Context, status string, limit int) ([]PilotLead, error) {
	if s.db == nil {
		return nil, ErrPersistenceUnavailable
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status == "" {
		status = "new"
	}
	if !validPilotStatus(status) {
		return nil, ErrInvalidAdminTransition
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, business_name, contact_name, email, phone, website, vertical,
       monthly_lead_band, message, status, source, created_at, updated_at
FROM tradepi_agent_pilot_leads
WHERE status=$1
ORDER BY created_at DESC, id DESC
LIMIT $2`, status, adminLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]PilotLead, 0)
	for rows.Next() {
		var item PilotLead
		if err := rows.Scan(&item.ID, &item.BusinessName, &item.ContactName, &item.Email, &item.Phone, &item.Website, &item.Vertical, &item.MonthlyLeadBand, &item.Message, &item.Status, &item.Source, &item.CreatedAt, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Service) AdminUpdatePilotLead(ctx context.Context, id int64, status string) error {
	if s.db == nil {
		return ErrPersistenceUnavailable
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if id <= 0 || !validPilotStatus(status) {
		return ErrInvalidAdminTransition
	}
	result, err := s.db.ExecContext(ctx, `UPDATE tradepi_agent_pilot_leads SET status=$2, updated_at=NOW() WHERE id=$1`, id, status)
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

func validPilotLead(lead PilotLead) bool {
	if lead.BusinessName == "" || lead.ContactName == "" || lead.Email == "" || lead.Website == "" {
		return false
	}
	if len(lead.BusinessName) > 160 || len(lead.ContactName) > 160 || len(lead.Email) > 254 || len(lead.Phone) > 80 || len(lead.Website) > 500 || len(lead.Message) > 4000 {
		return false
	}
	if _, err := mail.ParseAddress(lead.Email); err != nil {
		return false
	}
	parsed, err := url.Parse(lead.Website)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return false
	}
	return true
}

func validPilotStatus(status string) bool {
	switch status {
	case "new", "contacted", "qualified", "won", "lost":
		return true
	default:
		return false
	}
}
