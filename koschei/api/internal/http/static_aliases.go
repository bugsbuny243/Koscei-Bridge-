package http

import (
	"net/http"
	"path/filepath"
)

// registerStaticAliases keeps removed legacy product/demo URLs on the real
// production surfaces instead of serving stale standalone pages.
func registerStaticAliases(mux *http.ServeMux, staticDir string) {
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

	// Konsolidasyon: /scan/ ücretsiz taramanın kopyasıydı.
	mux.HandleFunc("/scan/", redirectPermanent("/safe-check"))
	mux.HandleFunc("/scan", redirectPermanent("/safe-check"))

	// Konsolidasyon: /security-radar premium panelin kopyasıydı.
	mux.HandleFunc("/security-radar", redirectPermanent("/dashboard"))
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

func redirectPermanent(target string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	}
}
