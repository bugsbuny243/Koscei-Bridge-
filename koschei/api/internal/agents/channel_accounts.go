package agents

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"net/url"
	"strings"
	"time"
)

type ChannelAccount struct {
	ID                int64     `json:"id"`
	TenantID          string    `json:"tenant_id"`
	Channel           string    `json:"channel"`
	AccountKey        string    `json:"account_key"`
	ProviderAccountID string    `json:"provider_account_id"`
	AllowedOrigin     string    `json:"allowed_origin"`
	Label             string    `json:"label"`
	Status            string    `json:"status"`
	UpdatedAt         time.Time `json:"updated_at"`
}

func (s *Service) ResolveChannelAccount(ctx context.Context, channel Channel, accountKey, providerAccountID string) (ChannelAccount, error) {
	if s.db == nil {
		return ChannelAccount{}, ErrPersistenceUnavailable
	}
	accountKey = strings.TrimSpace(accountKey)
	providerAccountID = strings.TrimSpace(providerAccountID)
	var item ChannelAccount
	var err error
	if accountKey != "" {
		err = s.db.QueryRowContext(ctx, `
SELECT id, tenant_id, channel, account_key, provider_account_id, allowed_origin, label, status, updated_at
FROM tradepi_agent_channel_accounts
WHERE channel=$1 AND account_key=$2 AND status='active'`, string(channel), accountKey).Scan(
			&item.ID, &item.TenantID, &item.Channel, &item.AccountKey, &item.ProviderAccountID,
			&item.AllowedOrigin, &item.Label, &item.Status, &item.UpdatedAt,
		)
	} else {
		err = s.db.QueryRowContext(ctx, `
SELECT id, tenant_id, channel, account_key, provider_account_id, allowed_origin, label, status, updated_at
FROM tradepi_agent_channel_accounts
WHERE channel=$1 AND provider_account_id=$2 AND status='active'`, string(channel), providerAccountID).Scan(
			&item.ID, &item.TenantID, &item.Channel, &item.AccountKey, &item.ProviderAccountID,
			&item.AllowedOrigin, &item.Label, &item.Status, &item.UpdatedAt,
		)
	}
	if err != nil {
		return ChannelAccount{}, ErrAdminRecordNotFound
	}
	return item, nil
}

func (s *Service) ChannelAccountByID(ctx context.Context, tenantID string, id int64) (ChannelAccount, error) {
	if s.db == nil {
		return ChannelAccount{}, ErrPersistenceUnavailable
	}
	var item ChannelAccount
	err := s.db.QueryRowContext(ctx, `
SELECT id, tenant_id, channel, account_key, provider_account_id, allowed_origin, label, status, updated_at
FROM tradepi_agent_channel_accounts
WHERE id=$1 AND tenant_id=$2 AND status='active'`, id, strings.TrimSpace(tenantID)).Scan(
		&item.ID, &item.TenantID, &item.Channel, &item.AccountKey, &item.ProviderAccountID,
		&item.AllowedOrigin, &item.Label, &item.Status, &item.UpdatedAt,
	)
	if err != nil {
		return ChannelAccount{}, ErrAdminRecordNotFound
	}
	return item, nil
}

func (s *Service) AdminChannelAccounts(ctx context.Context, tenantID string, limit int) ([]ChannelAccount, error) {
	if s.db == nil {
		return nil, ErrPersistenceUnavailable
	}
	rows, err := s.db.QueryContext(ctx, `
SELECT id, tenant_id, channel, account_key, provider_account_id, allowed_origin, label, status, updated_at
FROM tradepi_agent_channel_accounts
WHERE tenant_id=$1
ORDER BY updated_at DESC, id DESC
LIMIT $2`, strings.TrimSpace(tenantID), adminLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]ChannelAccount, 0)
	for rows.Next() {
		var item ChannelAccount
		if err := rows.Scan(&item.ID, &item.TenantID, &item.Channel, &item.AccountKey, &item.ProviderAccountID, &item.AllowedOrigin, &item.Label, &item.Status, &item.UpdatedAt); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *Service) AdminCreateChannelAccount(ctx context.Context, tenantID, channel, providerAccountID, allowedOrigin, label string) (ChannelAccount, error) {
	if s.db == nil {
		return ChannelAccount{}, ErrPersistenceUnavailable
	}
	tenantID = strings.TrimSpace(tenantID)
	channel = strings.ToLower(strings.TrimSpace(channel))
	providerAccountID = strings.TrimSpace(providerAccountID)
	allowedOrigin = strings.TrimRight(strings.TrimSpace(allowedOrigin), "/")
	label = strings.TrimSpace(label)
	if tenantID == "" || (channel != "web" && channel != "telegram" && channel != "whatsapp") {
		return ChannelAccount{}, ErrInvalidAdminTransition
	}
	if channel != "web" && providerAccountID == "" {
		return ChannelAccount{}, ErrInvalidAdminTransition
	}
	if channel == "web" && !validWidgetOrigin(allowedOrigin) {
		return ChannelAccount{}, ErrInvalidAdminTransition
	}
	key, err := newPublicAccountKey()
	if err != nil {
		return ChannelAccount{}, err
	}
	if channel == "web" && providerAccountID == "" {
		providerAccountID = key
	}
	var item ChannelAccount
	err = s.db.QueryRowContext(ctx, `
INSERT INTO tradepi_agent_channel_accounts (
    tenant_id, channel, account_key, provider_account_id, allowed_origin, label, status, updated_at
) VALUES ($1,$2,$3,$4,$5,$6,'active',NOW())
RETURNING id, tenant_id, channel, account_key, provider_account_id, allowed_origin, label, status, updated_at`,
		tenantID, channel, key, providerAccountID, allowedOrigin, label,
	).Scan(&item.ID, &item.TenantID, &item.Channel, &item.AccountKey, &item.ProviderAccountID, &item.AllowedOrigin, &item.Label, &item.Status, &item.UpdatedAt)
	if err != nil {
		return ChannelAccount{}, err
	}
	return item, nil
}

func (s *Service) AdminSetChannelAccountStatus(ctx context.Context, tenantID string, id int64, status string) error {
	if s.db == nil {
		return ErrPersistenceUnavailable
	}
	status = strings.ToLower(strings.TrimSpace(status))
	if status != "active" && status != "disabled" {
		return ErrInvalidAdminTransition
	}
	result, err := s.db.ExecContext(ctx, `
UPDATE tradepi_agent_channel_accounts
SET status=$3, updated_at=NOW()
WHERE id=$1 AND tenant_id=$2`, id, strings.TrimSpace(tenantID), status)
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

func validWidgetOrigin(value string) bool {
	if value == "" || value == "*" {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
		return false
	}
	return parsed.Path == "" && parsed.RawQuery == "" && parsed.Fragment == "" && parsed.User == nil
}

func newPublicAccountKey() (string, error) {
	buf := make([]byte, 24)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return "tpw_" + base64.RawURLEncoding.EncodeToString(buf), nil
}
