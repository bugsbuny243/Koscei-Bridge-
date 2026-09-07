package http

import (
	"net/http"
	"path/filepath"
)

// registerStaticAliases keeps removed legacy product/demo URLs on the real
// production surfaces instead of serving stale standalone pages.
func registerStaticAliases(mux *http.ServeMux, staticDir string) {
	// TradePI AI Agents shares the existing deployment but owns an isolated
	// namespace and does not alter Koschei Web3 security behavior.
	registerTradePIAgentRoutes(mux)
	registerTradePIAgentExtendedRoutes(mux)
	registerTradePIAgentFollowupRoutes(mux)
	registerTradePIAgentEscalationRoutes(mux)
	registerTradePIAgentTenantRoutes(mux)
	registerTradePIAgentChannelRoutes(mux)
	registerTradePIAgentPilotRoutes(mux)
	registerStaticFileAlias(mux, "/agents", filepath.Join(staticDir, "agents.html"))
	registerStaticFileAlias(mux, "/agents/", filepath.Join(staticDir, "agents.html"))
	registerStaticFileAlias(mux, "/agents/pilot", filepath.Join(staticDir, "agents-pilot.html"))
	registerStaticFileAlias(mux, "/agents/pilot/", filepath.Join(staticDir, "agents-pilot.html"))
	registerStaticFileAlias(mux, "/agents/admin", filepath.Join(staticDir, "agents-admin.html"))
	registerStaticFileAlias(mux, "/agents/admin/", filepath.Join(staticDir, "agents-admin.html"))
	registerStaticFileAlias(mux, "/agents/install", filepath.Join(staticDir, "agents-install.html"))
	registerStaticFileAlias(mux, "/agents/install/", filepath.Join(staticDir, "agents-install.html"))

	// The Customer Panel is the single customer-facing operational surface.
	// The only live capability preserved from the former classic scan console is
	// read-only Solana transaction simulation, now mounted in the panel. Token
	// and deep-scan compatibility URLs land on capability truth rather than
	// reviving controls whose persistence/entitlement contract is not live.
	for _, route := range []string{"/scan", "/scan/", "/scan.html", "/transaction-shield", "/transaction-shield/", "/transaction-shield.html"} {
		registerCanonicalRedirect(mux, route, "/dashboard#transaction-preflight")
	}
	for _, route := range []string{"/safe-check", "/safe-check/", "/safe-check.html", "/security-radar", "/security-radar/", "/security-radar.html"} {
		registerCanonicalRedirect(mux, route, "/dashboard#capabilities")
	}

	dashboardRoutes := []string{
		"/airdrop-checker",
		"/cross-chain-risk",
		"/funding-assistant",
		"/graph",
		"/hub",
		"/mev-shield",
		"/portfolio",
		"/program-scanner",
		"/project-radar",
		"/radar",
		"/risk",
		"/risk-v2",
		"/smart-money",
		"/sybil-check",
		"/token-scanner",
		"/tools",
		"/tx-decoder",
		"/tx-decoder-pro",
		"/wallet-score",
	}
	for _, route := range dashboardRoutes {
		registerStaticFileAlias(mux, route, filepath.Join(staticDir, "dashboard.html"))
	}

	// Former standalone customer functions no longer get a second product page.
	// Feedback and Exposure both require persistence-backed state in the current
	// implementation, while production is intentionally stateless. Their legacy
	// URLs land on read-only truth anchors, not interactive controls.
	for _, route := range []string{"/feedback", "/feedback/", "/feedback.html"} {
		registerCanonicalRedirect(mux, route, "/dashboard#feedback")
	}
	for _, route := range []string{"/exposure-report", "/exposure-report/", "/exposure-report.html"} {
		registerCanonicalRedirect(mux, route, "/dashboard#exposure")
	}

	// These pages describe retired product/payment models rather than current
	// Koschei Web3 capabilities. Do not leave stale public copy addressable.
	for _, route := range []string{"/security-ecosystem", "/security-ecosystem/", "/security-ecosystem.html"} {
		registerCanonicalRedirect(mux, route, "/dashboard#capabilities")
	}
	for _, route := range []string{"/token-vesting", "/token-vesting/", "/token-vesting.html"} {
		registerCanonicalRedirect(mux, route, "/")
	}

	// These legacy .html assets currently contain only client-side redirects to
	// /dashboard. Own the compatibility URLs in the Go router first so a future
	// tombstone-file cleanup cannot silently turn them into 404s or stale pages.
	for _, route := range []string{
		"/airdrop-checker.html",
		"/cross-chain-risk.html",
		"/funding-assistant.html",
		"/grant-writer.html",
		"/intelligence-graph.html",
		"/jarvis.html",
		"/mev-shield.html",
		"/program-scanner.html",
		"/radar.html",
		"/smart-money.html",
		"/unified.html",
	} {
		registerCanonicalRedirect(mux, route, "/dashboard")
	}

	registerStaticFileAlias(mux, "/docs/api", filepath.Join(staticDir, "docs-api.html"))
	registerStaticFileAlias(mux, "/docs/sdk", filepath.Join(staticDir, "docs-sdk.html"))
}

func registerCanonicalRedirect(mux *http.ServeMux, route, target string) {
	mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != route {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
}

func registerStaticFileAlias(mux *http.ServeMux, route, filename string) {
	mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != route {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		http.ServeFile(w, r, filename)
	})
}