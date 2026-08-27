package http

import (
	"encoding/json"
	"net/http"
	"time"
)

type routeInventoryGroup struct {
	Name   string   `json:"name"`
	Auth   string   `json:"auth"`
	Routes []string `json:"routes"`
}

func ownerRouteMap(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	_ = json.NewEncoder(w).Encode(map[string]any{
		"ok":           true,
		"generated_at": time.Now().UTC().Format(time.RFC3339),
		"source":       "server_boot_chain",
		"access_model": "public_free_core_plus_saas_entitlements",
		"groups":       productionRouteInventory(),
		"rules": []string{
			"A handler is live only when registered in the server boot chain.",
			"The production route inventory is contract-tested against literal API registrations.",
			"Public Safe Check and basic token fundamentals are available without a paid plan.",
			"Public SOC discovery exposes only explicitly published immutable dossiers; a stored dossier is private by default.",
			"A customer session identifies the account; paid product authorization is derived only from an active SaaS entitlement.",
			"KOSCH holdings, wallet balances and legacy holder tiers do not authorize product routes, API keys, quotas or discounts.",
			"Starter unlocks paid investigation routes; Professional unlocks advanced radar and watchlists; Enterprise unlocks API keys and webhook management.",
			"Developer API keys remain identity credentials and require an active Enterprise entitlement for developer routes.",
			"Paddle checkout is customer-authenticated; entitlement activation occurs only after a verified Paddle webhook binds the completed transaction to the configured plan price.",
			"Legacy KOSCH access endpoints are compatibility tombstones only and cannot grant access.",
			"Evidence-backed verdicts must not be signed without verified evidence.",
			"Recipient fate investigation is mint-specific ATA-only and never queries recipient-wide signature history.",
			"Canonical investigation jobs accept token mint, wallet or token-account targets and continue after the HTTP request ends.",
			"Owner, customer and automatic Pump discovery routes feed the same canonical investigation worker.",
			"Signed medium-or-higher ARVIS verdicts and non-allow transaction guard decisions enter the durable alert pipeline.",
			"Enterprise defense validation recomputes isolated execution evidence and authenticates independent collector observations; it never submits mainnet transactions or mutates production controls.",
			"Enterprise Safe execution assurance independently recomputes the complete Safe EIP-712 transaction hash and Execution Proof and requires a fresh Ed25519 attestation from the server-configured trusted producer before ALLOW; caller-selected trust material cannot authorize the request.",
			"Defense OS routes are registered only when KOSCHEI_DEFENSE_OS_ENABLED=true.",
		},
	})
}

func productionRouteInventory() []routeInventoryGroup {
	return []routeInventoryGroup{
		{Name: "public_and_system", Auth: "public_or_mixed", Routes: []string{
			"GET /health", "GET /api/config", "GET /api/version", "GET /api/web3/health", "GET /api/web3/health/logs",
			"POST /api/analytics/event", "POST /api/arvis/preflight", "POST /api/token/scan", "GET /api/v1/risk/badge",
			"GET /api/public/impact", "GET /api/public/metrics", "GET /api/public/cases", "GET /api/public/soc/feed",
			"GET /api/public/token/status", "GET /api/public/token/readiness", "GET /api/public/scan-history", "POST /api/public/transaction-simulate",
			"GET /api/agent/health", "POST /api/agent/wallet-score", "POST /api/agent/risk-summary", "POST /api/agent/metadata-template", "POST /api/agent/chain-health",
		}},
		{Name: "identity", Auth: "mixed", Routes: []string{
			"POST /api/auth/provision", "POST /api/auth/register", "POST /api/auth/login", "GET /api/auth/neon-login", "GET /api/auth/neon-register", "GET /api/auth/neon-callback", "GET /api/me",
		}},
		{Name: "account_and_saas_access", Auth: "customer_session_plus_enterprise_for_api_keys", Routes: []string{
			"/api/account/api-keys", "/api/account/api-keys/",
			"POST /api/auth/wallet/challenge", "POST /api/auth/wallet/verify", "GET /api/auth/wallet/status",
			"POST /api/auth/wallet/unlink", "GET /api/auth/token-access", "GET /api/auth/premium-access",
		}},
		{Name: "billing", Auth: "customer_session_or_verified_provider_webhook", Routes: []string{
			"POST /api/paddle/checkout", "POST /api/v1/paddle/checkout", "POST /api/paddle/webhook",
		}},
		{Name: "owner", Auth: "owner_session", Routes: []string{
			"POST /api/owner/login", "POST /api/owner/logout", "GET /api/owner/command-center", "GET /api/owner/operations",
			"GET /api/owner/arvis", "POST /api/owner/arvis/scan", "POST /api/owner/radar/unified", "POST /api/owner/radar/jobs", "GET /api/owner/radar/jobs/",
			"POST /api/owner/radar/funding-corpus/warmup", "GET /api/owner/creator-intelligence", "GET /api/owner/wallet-linkage", "GET /api/owner/actor-intelligence",
			"GET /api/owner/actor-memory/matches", "GET /api/owner/radar/continuity", "GET /api/owner/radar/provider-memory",
			"GET /api/owner/defense/tracks", "POST /api/owner/defense/investigate", "POST /api/owner/defense/actor-acceptance", "POST /api/owner/defense/distribution",
			"POST /api/owner/web3/shield/preflight", "POST /api/owner/web3/transaction-guard", "POST /api/owner/web3/transaction-guard/state-recheck", "POST /api/owner/web3/address-poisoning/check", "POST /api/owner/web3/defense-validation", "POST /api/owner/web3/execution-assurance/safe/verify",
			"/api/owner/radar/sources", "GET /api/owner/kosch-access", "GET /api/owner/security-events", "GET /api/owner/route-map", "/api/owner/feedback",
			"GET /api/owner/users", "POST /api/owner/users/ban", "POST /api/owner/users/remove", "POST /api/owner/command", "POST /api/owner/brain", "/api/owner/chat", "GET /api/owner/health", "GET /api/owner/status",
			"POST /api/owner/dossier/publications", "POST /api/owner/arvis/acceptance",
		}},
		{Name: "premium_radar_and_reports", Auth: "customer_session_plus_saas_entitlement", Routes: []string{
			"POST /api/v1/token/extensions", "POST /api/v1/address-poisoning/check", "POST /api/customer/web3/transaction-preflight",
			"POST /api/v1/radar/check", "POST /api/v1/radar/jobs", "GET /api/v1/radar/jobs/", "GET /api/v1/radar/detail", "GET /api/v1/radar/feed",
			"GET /api/v1/radar/creator-intelligence", "GET /api/v1/radar/actor-intelligence", "GET /api/v1/radar/graph", "GET /api/v1/radar/exposure", "POST /api/v1/radar/court",
			"POST /api/jobs/token-scan", "GET /api/jobs/",
		}},
		{Name: "developer_api", Auth: "api_key_plus_enterprise_entitlement", Routes: []string{
			"POST /api/v1/scan/token", "GET /api/v1/usage", "POST /api/v1/shield/preflight",
			"POST /api/v1/shield/transaction", "POST /api/v1/shield/state-recheck", "POST /api/v1/shield/address-poisoning",
			"POST /api/v1/defense/validation", "POST /api/v1/execution-assurance/safe/verify",
		}},
		{Name: "dossier", Auth: "mixed", Routes: []string{
			"POST /api/v1/dossier/",
		}},
		{Name: "watchlist_and_webhooks", Auth: "professional_or_enterprise_saas_entitlement", Routes: []string{
			"/api/watchlist", "POST /api/watchlist/refresh", "/api/watchlist/alerts", "/api/watchlist/",
			"/api/webhooks", "/api/webhooks/", "/api/webhooks/security-alerts", "/api/webhooks/deliveries", "/api/webhooks/deliveries/",
		}},
		{Name: "defense_os_opt_in", Auth: "owner_session_and_feature_gate", Routes: []string{
			"/api/owner/defense/artifacts", "/api/owner/defense/knowledge", "/api/owner/defense/lab", "/api/owner/defense/deployment",
			"/api/owner/defense/source-import", "/api/owner/defense/worker-jobs", "/api/owner/defense/reproduction", "/api/owner/defense/sentinel",
			"/api/owner/defense/harness", "/api/owner/defense/harness-execution", "/api/owner/defense/harness-materialization", "/api/owner/defense/litesvm-execution",
		}},
	}
}
