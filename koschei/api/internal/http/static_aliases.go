package http

import (
	"net/http"
	"path/filepath"
)

// registerStaticAliases keeps removed legacy product/demo URLs on the real
// production surfaces instead of serving stale standalone pages.
func registerStaticAliases(mux *http.ServeMux, staticDir string) {
	// There is one customer-facing investigation surface. Legacy scanner URLs
	// preserve their intent through a mode query, but no longer render separate
	// products with overlapping forms and verdict language.
	for _, route := range []string{"/safe-check", "/safe-check.html"} {
		registerScanModeRedirect(mux, route, "quick")
	}
	for _, route := range []string{"/transaction-shield", "/transaction-shield.html"} {
		registerScanModeRedirect(mux, route, "transaction")
	}
	for _, route := range []string{"/security-radar", "/security-radar.html"} {
		registerScanModeRedirect(mux, route, "deep")
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
