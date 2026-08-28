package agents

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"regexp"
	"strings"
)

var tenantSlugSanitizer = regexp.MustCompile(`[^a-z0-9]+`)

type WebTenantOnboarding struct {
	Tenant  TenantSettings `json:"tenant"`
	Account ChannelAccount `json:"account"`
}

func (s *Service) AdminOnboardWebTenant(ctx context.Context, displayName, vertical, timezone, language, allowedOrigin, label string, assignmentSLAMinutes, followupDelayMinutes int) (WebTenantOnboarding, error) {
	if s.db == nil {
		return WebTenantOnboarding{}, ErrPersistenceUnavailable
	}
	displayName = strings.TrimSpace(displayName)
	vertical = strings.ToLower(strings.TrimSpace(vertical))
	timezone = strings.TrimSpace(timezone)
	language = strings.ToLower(strings.TrimSpace(language))
	allowedOrigin = strings.TrimRight(strings.TrimSpace(allowedOrigin), "/")
	label = strings.TrimSpace(label)
	if displayName == "" || !validWidgetOrigin(allowedOrigin) {
		return WebTenantOnboarding{}, ErrInvalidAdminTransition
	}
	if vertical == "" {
		vertical = "general"
	}
	if timezone == "" {
		timezone = "Europe/Istanbul"
	}
	if language == "" {
		language = "tr"
	}
	if assignmentSLAMinutes == 0 {
		assignmentSLAMinutes = 10
	}
	if followupDelayMinutes == 0 {
		followupDelayMinutes = 120
	}
	if assignmentSLAMinutes < 1 || assignmentSLAMinutes > 1440 || followupDelayMinutes < 5 || followupDelayMinutes > 10080 {
		return WebTenantOnboarding{}, ErrInvalidAdminTransition
	}
	if label == "" {
		label = "Main website"
	}

	tenantID, err := newTenantID(displayName)
	if err != nil {
		return WebTenantOnboarding{}, err
	}
	accountKey, err := newPublicAccountKey()
	if err != nil {
		return WebTenantOnboarding{}, err
	}

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return WebTenantOnboarding{}, err
	}
	defer tx.Rollback()

	var out WebTenantOnboarding
	err = tx.QueryRowContext(ctx, `
INSERT INTO tradepi_agent_tenants (
    tenant_id, display_name, vertical, timezone, language,
    assignment_sla_minutes, followup_delay_minutes, status, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,$7,'active',NOW())
RETURNING tenant_id, display_name, vertical, timezone, language,
          assignment_sla_minutes, followup_delay_minutes, status, updated_at`,
		tenantID, displayName, vertical, timezone, language, assignmentSLAMinutes, followupDelayMinutes,
	).Scan(
		&out.Tenant.TenantID,
		&out.Tenant.DisplayName,
		&out.Tenant.Vertical,
		&out.Tenant.Timezone,
		&out.Tenant.Language,
		&out.Tenant.AssignmentSLAMinutes,
		&out.Tenant.FollowupDelayMinutes,
		&out.Tenant.Status,
		&out.Tenant.UpdatedAt,
	)
	if err != nil {
		return WebTenantOnboarding{}, err
	}

	err = tx.QueryRowContext(ctx, `
INSERT INTO tradepi_agent_channel_accounts (
    tenant_id, channel, account_key, provider_account_id, allowed_origin, label, status, updated_at
) VALUES ($1,'web',$2,$2,$3,$4,'active',NOW())
RETURNING id, tenant_id, channel, account_key, provider_account_id, allowed_origin, label, status, updated_at`,
		tenantID, accountKey, allowedOrigin, label,
	).Scan(
		&out.Account.ID,
		&out.Account.TenantID,
		&out.Account.Channel,
		&out.Account.AccountKey,
		&out.Account.ProviderAccountID,
		&out.Account.AllowedOrigin,
		&out.Account.Label,
		&out.Account.Status,
		&out.Account.UpdatedAt,
	)
	if err != nil {
		return WebTenantOnboarding{}, err
	}

	if err := tx.Commit(); err != nil {
		return WebTenantOnboarding{}, err
	}
	return out, nil
}

func newTenantID(displayName string) (string, error) {
	base := strings.ToLower(strings.TrimSpace(displayName))
	base = tenantSlugSanitizer.ReplaceAllString(base, "-")
	base = strings.Trim(base, "-")
	if base == "" {
		base = "tenant"
	}
	if len(base) > 32 {
		base = strings.Trim(base[:32], "-")
	}
	buf := make([]byte, 4)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base + "-" + hex.EncodeToString(buf), nil
}
