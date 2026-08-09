package services

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"time"
)

type PumpPortalTradeStreamHealth struct {
	Available          bool                           `json:"available"`
	Status             string                         `json:"status"`
	APIKeyConfigured   bool                           `json:"api_key_configured"`
	WalletConfigured   bool                           `json:"wallet_public_key_configured"`
	Runtime            PumpPortalTradeRuntimeSnapshot `json:"runtime"`
	TotalTrades        int64                          `json:"total_trades"`
	Trades15m          int64                          `json:"trades_15m"`
	DistinctMints15m   int64                          `json:"distinct_mints_15m"`
	DistinctTraders15m int64                          `json:"distinct_traders_15m"`
	LastTradeAt        *time.Time                      `json:"last_trade_at,omitempty"`
	Limitations        []string                       `json:"limitations"`
	Policy             map[string]any                 `json:"policy"`
}

func LoadPumpPortalTradeStreamHealth(ctx context.Context, db *sql.DB, now time.Time) (PumpPortalTradeStreamHealth, error) {
	out := PumpPortalTradeStreamHealth{
		Status:           "unavailable",
		APIKeyConfigured: strings.TrimSpace(os.Getenv("PUMPPORTAL_API_KEY")) != "",
		WalletConfigured: strings.TrimSpace(os.Getenv("PUMPPORTAL_WALLET_PUBLIC_KEY")) != "",
		Runtime:          CurrentPumpPortalTradeRuntime(),
		Limitations:      []string{},
		Policy: map[string]any{
			"api_key_secret_is_never_returned":         true,
			"provider_notice_payload_is_not_returned":  true,
			"wallet_balance_is_not_assumed":            true,
			"absence_of_trades_is_not_safety_evidence": true,
			"trade_delivery_is_not_verdict_authority":  true,
		},
	}
	if !out.APIKeyConfigured {
		out.Available = true
		out.Status = "not_configured"
		out.Limitations = append(out.Limitations, "PumpPortal trade subscriptions require an API key; creation and migration discovery can still operate without trade-stream entitlement.")
		return out, nil
	}
	if db == nil {
		out.Limitations = append(out.Limitations, "Trade ledger database is unavailable, so delivery cannot be verified.")
		return out, nil
	}
	if now.IsZero() {
		now = time.Now().UTC()
	} else {
		now = now.UTC()
	}
	var lastTrade sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT
			count(*),
			count(*) FILTER (WHERE created_at >= $1 - interval '15 minutes'),
			count(DISTINCT mint) FILTER (WHERE created_at >= $1 - interval '15 minutes'),
			count(DISTINCT trader) FILTER (WHERE created_at >= $1 - interval '15 minutes'),
			max(created_at)
		FROM token_trade_events
	`, now).Scan(&out.TotalTrades, &out.Trades15m, &out.DistinctMints15m, &out.DistinctTraders15m, &lastTrade)
	if err != nil {
		if isUndefinedTableError(err) {
			out.Limitations = append(out.Limitations, "Trade ledger schema is not available yet.")
			return out, nil
		}
		return PumpPortalTradeStreamHealth{}, err
	}
	out.Available = true
	if lastTrade.Valid {
		value := lastTrade.Time.UTC()
		out.LastTradeAt = &value
	}
	out.Status = classifyPumpPortalTradeStreamHealth(out, now)
	if out.Runtime.Status == "subscription_rejected" {
		out.Status = "subscription_rejected"
		out.Limitations = append(out.Limitations,
			"PumpPortal returned a bounded provider notice classified as a trade-subscription rejection. The raw provider payload is intentionally not exposed.")
	}
	if out.Status == "no_trade_observed" {
		out.Limitations = append(out.Limitations,
			"An API key is configured, but Koschei has not durably observed a PumpPortal trade. Current PumpPortal trade entitlement and linked-wallet funding are therefore unverified.")
	}
	if out.APIKeyConfigured && !out.WalletConfigured {
		out.Limitations = append(out.Limitations,
			"No PumpPortal wallet public key is configured locally, so Koschei cannot independently inspect the linked wallet funding state.")
	}
	return out, nil
}

func classifyPumpPortalTradeStreamHealth(health PumpPortalTradeStreamHealth, now time.Time) string {
	if !health.APIKeyConfigured {
		return "not_configured"
	}
	if !health.Available {
		return "unavailable"
	}
	if health.LastTradeAt == nil || health.TotalTrades == 0 {
		return "no_trade_observed"
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	age := now.UTC().Sub(health.LastTradeAt.UTC())
	if age <= 15*time.Minute && health.Trades15m > 0 {
		return "observed"
	}
	if age <= time.Hour {
		return "idle"
	}
	return "stale"
}
