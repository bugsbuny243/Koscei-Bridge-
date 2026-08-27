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
	registerStaticFileAlias(mux, "/agents", filepath.Join(staticDir, "agents.html"))
	registerStaticFileAlias(mux, "/agents/", filepath.Join(staticDir, "agents.html"))
	registerStaticFileAlias(mux, "/agents/admin", filepath.Join(staticDir, "agents-admin.html"))
	registerStaticFileAlias(mux, "/agents/admin/", filepath.Join(staticDir, "agents-admin.html"))

	// There is one customer-facing investigation surface. Legacy scanner URLs
	// preserve their intent through a mode query, but no longer render separate
	// products with overlapping forms and verdict language.
	for _, route := range []string{"/safe-check", "/safe-check/", "/safe-check.html"} {
		registerScanModeRedirect(mux, route, "quick")
	}
	for _, route := range []string{"/transaction-shield", "/transaction-shield/", "/transaction-shield.html"} {
		registerScanModeRedirect(mux, route, "transaction")
	}
	for _, route := range []string{"/security-radar", "/security-radar/", "/security-radar.html"} {
		registerScanModeRedirect(mux, route, "deep")
	}

	// Paddle transaction checkout URLs are built from this canonical default
	// payment link and append the _ptxn transaction query parameter.
	for _, route := range []string{"/paddle-checkout", "/paddle-checkout/", "/paddle-checkout.html"} {
		registerStaticFileAlias(mux, route, filepath.Join(staticDir, "paddle-checkout.html"))
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

	// These legacy .html assets currently contain only client-side redirects to
	// /dashboard. Own the compatibility URLs in the Go router first so a future
	// tombstone-file cleanup cannot silently turn them into 404s or stale pages.
	// The files intentionally remain in public/ until reference/audit cleanup is
	// complete; explicit routes take precedence over FileServer fallback.
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
	mux.HandleFunc("/scan/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		http.ServeFile(w, r, filepath.Join(staticDir, "scan.html"))
	})
}

func registerScanModeRedirect(mux *http.ServeMux, route, mode string) {
	mux.HandleFunc(route, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != route {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		query := r.URL.Query()
		query.Set("mode", mode)
		target := "/scan"
		if encoded := query.Encode(); encoded != "" {
			target += "?" + encoded
		}
		http.Redirect(w, r, target, http.StatusPermanentRedirect)
	})
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
