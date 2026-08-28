package agents

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

type TenantSettings struct {
	TenantID              string    `json:"tenant_id"`
	DisplayName           string    `json:"display_name"`
	Vertical              string    `json:"vertical"`
	Timezone              string    `json:"timezone"`
	Language              string    `json:"language"`
	AssignmentSLAMinutes  int       `json:"assignment_sla_minutes"`
	FollowupDelayMinutes  int       `json:"followup_delay_minutes"`
	Status                string    `json:"status"`
	UpdatedAt             time.Time `json:"updated_at"`
}

func (s *Service) AdminTenantSettings(ctx context.Context, tenantID string) (TenantSettings, error) {
	if s.db == nil {
		return TenantSettings{}, ErrPersistenceUnavailable
	}
	tenantID = strings.TrimSpace(tenantID)
	var out TenantSettings
	err := s.db.QueryRowContext(ctx, `
SELECT tenant_id, display_name, vertical, timezone, language,
       assignment_sla_minutes, followup_delay_minutes, status, updated_at
FROM tradepi_agent_tenants
WHERE tenant_id=$1`, tenantID).Scan(
		&out.TenantID,
		&out.DisplayName,
		&out.Vertical,
		&out.Timezone,
		&out.Language,
		&out.AssignmentSLAMinutes,
		&out.FollowupDelayMinutes,
		&out.Status,
		&out.UpdatedAt,
	)
	if err == sql.ErrNoRows {
		return TenantSettings{
			TenantID: tenantID,
			Vertical: "general",
			Timezone: "UTC",
			Language: "tr",
			AssignmentSLAMinutes: 10,
			FollowupDelayMinutes: 120,
			Status: "active",
		}, nil
	}
	if err != nil {
		return TenantSettings{}, err
	}
	return out, nil
}

func (s *Service) AdminUpsertTenantSettings(ctx context.Context, settings TenantSettings) error {
	if s.db == nil {
		return ErrPersistenceUnavailable
	}
	settings.TenantID = strings.TrimSpace(settings.TenantID)
	settings.DisplayName = strings.TrimSpace(settings.DisplayName)
	settings.Vertical = strings.ToLower(strings.TrimSpace(settings.Vertical))
	settings.Timezone = strings.TrimSpace(settings.Timezone)
	settings.Language = strings.ToLower(strings.TrimSpace(settings.Language))
	settings.Status = strings.ToLower(strings.TrimSpace(settings.Status))
	if settings.TenantID == "" || settings.DisplayName == "" {
		return ErrInvalidAdminTransition
	}
	if settings.Vertical == "" {
		settings.Vertical = "general"
	}
	if settings.Timezone == "" {
		settings.Timezone = "UTC"
	}
	if settings.Language == "" {
		settings.Language = "tr"
	}
	if settings.Status == "" {
		settings.Status = "active"
	}
	if settings.Status != "active" && settings.Status != "paused" {
		return ErrInvalidAdminTransition
	}
	if settings.AssignmentSLAMinutes < 1 || settings.AssignmentSLAMinutes > 1440 {
		return ErrInvalidAdminTransition
	}
	if settings.FollowupDelayMinutes < 5 || settings.FollowupDelayMinutes > 10080 {
		return ErrInvalidAdminTransition
	}
	_, err := s.db.ExecContext(ctx, `
INSERT INTO tradepi_agent_tenants (
    tenant_id, display_name, vertical, timezone, language,
    assignment_sla_minutes, followup_delay_minutes, status, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NOW())
ON CONFLICT (tenant_id) DO UPDATE SET
    display_name=EXCLUDED.display_name,
    vertical=EXCLUDED.vertical,
    timezone=EXCLUDED.timezone,
    language=EXCLUDED.language,
    assignment_sla_minutes=EXCLUDED.assignment_sla_minutes,
    followup_delay_minutes=EXCLUDED.followup_delay_minutes,
    status=EXCLUDED.status,
    updated_at=NOW()`,
		settings.TenantID,
		settings.DisplayName,
		settings.Vertical,
		settings.Timezone,
		settings.Language,
		settings.AssignmentSLAMinutes,
		settings.FollowupDelayMinutes,
		settings.Status,
	)
	return err
}
