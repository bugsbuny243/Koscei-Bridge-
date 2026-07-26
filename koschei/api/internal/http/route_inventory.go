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
		"access_model": "public_security_core_plus_authenticated_creation_and_premium_automation",
		"groups":       productionRouteInventory(),
		"rules": []string{
			"A handler is live only when registered in the server boot chain.",
			"Safe Check, public cases, live SOC, Program Audit and published program-risk evidence are public product surfaces.",
			"A dossier, artifact or program-risk record is private by default; its creator controls visibility and owner access is moderation only.",
			"A customer session or API key identifies the creator of scans, dossiers, artifacts, monitors and publications.",
			"Customer Program Lab analysis is deterministic and static-only; it cannot execute commands, deploy programs or send transactions.",
			"Radar history, graph, exposure, automation and developer API may require the configured KOSCH tier.",
			"Developer API keys remain identity credentials and never bypass evidence or entitlement checks.",
			"Evidence-backed verdicts must not be signed without verified evidence.",
			"Public pages show security decisions, findings, evidence and actions; internal worker and acceptance state remains operational telemetry.",
			"Canonical investigation jobs accept token mint, wallet or token-account targets and continue after the HTTP request ends.",
			"Signed ARVIS decisions and non-allow transaction guard results enter the durable alert pipeline.",
		},
	})
}

func productionRouteInventory() []routeInventoryGroup {
	return []routeInventoryGroup{
		{Name: "free_core", Auth: "public_rate_limited", Routes: []string{
			"POST /api/arvis/preflight", "POST /api/token/scan", "GET /api/v1/risk/badge",
			"GET /api/public/impact", "GET /api/public/metrics", "GET /api/public/cases", "GET /api/public/soc/feed",
			"GET /api/public/program-risks", "GET /api/public/program-risks/{ref}", "GET /program-risk/{ref}", "GET /case/{ref}", "GET /dossier/{ref}", "GET /program-audit", "GET /api/web3/health",
		}},
		{Name: "identity", Auth: "mixed", Routes: []string{
			"GET /health", "GET /api/config", "POST /api/auth/register", "POST /api/auth/login", "GET /api/me",
			"GET /api/web3/health/logs", "POST /api/analytics/event",
		}},
		{Name: "authenticated_security_creation", Auth: "customer_session_or_api_key", Routes: []string{
			"POST /api/v1/dossier/{target}", "POST /api/v1/dossier/publications", "GET|POST /api/v1/defense/sentinel",
			"GET|POST /api/v1/defense/artifacts", "GET|POST /api/v1/defense/lab", "POST /api/v1/program-risks/publications",
		}},
		{Name: "account_and_kosch_access", Auth: "customer_session_plus_kosch_for_api_keys", Routes: []string{
			"GET /api/account/api-keys", "POST /api/account/api-keys", "POST /api/account/api-keys/{id}/revoke",
			"POST /api/auth/wallet/challenge", "POST /api/auth/wallet/verify", "GET /api/auth/wallet/status",
			"POST /api/auth/wallet/unlink", "GET /api/auth/token-access", "GET /api/auth/premium-access",
		}},
		{Name: "owner_moderation_and_operations", Auth: "owner_session", Routes: []string{
			"POST /api/owner/login", "POST /api/owner/logout", "GET /api/owner/command-center", "GET /api/owner/route-map",
			"POST /api/owner/radar/unified", "POST /api/owner/radar/jobs", "GET /api/owner/radar/jobs/{id}",
			"GET /api/owner/defense/tracks", "POST /api/owner/defense/investigate", "POST /api/owner/defense/distribution",
			"POST /api/owner/dossier/publications", "GET|POST /api/owner/defense/litesvm-execution",
			"GET /api/owner/users", "POST /api/owner/users/ban", "POST /api/owner/users/remove", "POST /api/owner/command",
			"POST /api/owner/brain", "/api/owner/chat", "GET /api/owner/health", "GET /api/owner/status",
		}},
		{Name: "premium_radar_and_reports", Auth: "customer_session_plus_kosch", Routes: []string{
			"POST /api/v1/token/extensions", "POST /api/v1/address-poisoning/check",
			"GET /api/v1/radar/feed", "POST /api/v1/radar/check", "POST /api/v1/radar/jobs", "GET /api/v1/radar/jobs/{id}",
			"POST /api/jobs/token-scan", "GET /api/jobs/{id}", "GET /api/v1/radar/graph", "GET /api/v1/radar/exposure",
		}},
		{Name: "developer_api", Auth: "api_key_plus_live_kosch_holder", Routes: []string{
			"POST /api/v1/scan/token", "GET /api/v1/usage", "POST /api/v1/shield/preflight",
			"POST /api/v1/shield/transaction", "POST /api/v1/shield/address-poisoning",
		}},
		{Name: "watchlist_and_webhooks", Auth: "customer_session_plus_kosch", Routes: []string{
			"/api/watchlist", "POST /api/watchlist/refresh", "/api/watchlist/alerts", "/api/watchlist/{id}",
			"/api/webhooks", "/api/webhooks/{id}", "GET|POST /api/webhooks/security-alerts", "/api/webhooks/deliveries", "/api/webhooks/deliveries/{id}",
		}},
	}
}
