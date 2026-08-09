package http

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"koschei/api/internal/handlers"
)

var databaseOptionalAPIPaths = func() map[string]struct{} {
	paths := []string{
		"/api/me",
		"/api/v1/risk/badge",
		"/api/version",
		"/api/config",
		"/api/auth/register",
		"/api/auth/login",
		"/api/auth/provision",
		"/api/auth/neon-login",
		"/api/auth/neon-register",
		"/api/auth/neon-callback",
		"/api/owner/login",
		"/api/owner/logout",
		"/api/owner/command-center",
		"/api/public/impact",
		"/api/public/metrics",
		"/api/public/token/status",
		"/api/public/token/readiness",
		"/api/web3/health",
		"/api/analytics/event",
		"/api/arvis/preflight",
		"/api/token/scan",
	}
	result := make(map[string]struct{}, len(paths))
	for _, path := range paths {
		result[path] = struct{}{}
	}
	return result
}()

func allowedWithoutDatabase(path string) bool {
	_, ok := databaseOptionalAPIPaths[path]
	return ok
}

func apiReadiness(db *sql.DB, next http.Handler) http.Handler {
	setSecurityAuditDB(db)
	protected := bodyLimit(sensitiveRateLimit(db, next))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := r.URL.Path
		if strings.HasPrefix(path, "/api/") && !allowedWithoutDatabase(path) && db == nil {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusServiceUnavailable)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "database unavailable"})
			return
		}
		protected.ServeHTTP(w, r)
	})
}

func registerLegacyDashboardRedirects(mux *http.ServeMux) {
	routes := []string{"/airdrop-checker", "/cross-chain-risk", "/funding-assistant", "/grant", "/grant-writer", "/graph", "/hub", "/intelligence-graph", "/liquidity-radar", "/mev-shield", "/portfolio", "/program-scanner", "/project-radar", "/radar", "/risk", "/risk-v2", "/smart-money", "/solana-risk-scanner", "/solana-token-scanner", "/solana-tx-decoder", "/sybil-check", "/sybil-checker", "/token-scanner", "/tx-decoder", "/tx-decoder-pro", "/unified", "/wallet-score"}
	for _, route := range routes {
		mux.HandleFunc(route, redirectToDashboard)
		mux.HandleFunc(route+".html", redirectToDashboard)
	}
}

func redirectToDashboard(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	http.Redirect(w, r, "/dashboard", http.StatusFound)
}

func ownerPageHandler(staticDir string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if staticDir != "" {
			ownerPath := filepath.Join(staticDir, "owner.html")
			if info, err := os.Stat(ownerPath); err == nil && !info.IsDir() {
				http.ServeFile(w, r, ownerPath)
				return
			}
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte("<!doctype html><html lang=tr><meta charset=utf-8><title>Koschei Owner</title><body><h1>Owner paneli bulunamadı.</h1></body></html>"))
	}
}

func ownerOnly(h *handlers.Handler, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.OwnerAuth(w, r) {
			return
		}
		next(w, r)
	}
}

func requiresDB(h *handlers.Handler, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !h.RequireDB(w) {
			return
		}
		next(w, r)
	}
}

func method(m string, next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != m {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		next(w, r)
	}
}

func cors(next http.Handler, origin string) http.Handler {
	allowedOrigins := buildAllowedOrigins(origin)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if allowed := allowedCORSOrigin(r.Header.Get("Origin"), allowedOrigins); allowed != "" {
			w.Header().Set("Access-Control-Allow-Origin", allowed)
			w.Header().Set("Vary", "Origin")
		}
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization, X-API-Key, X-Koschei-Source-Id, X-CSRF-Token")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PATCH, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Credentials", "true")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func buildAllowedOrigins(configured string) map[string]struct{} {
	origins := map[string]struct{}{
		"https://tradepigloball.co":     {},
		"https://www.tradepigloball.co": {},
	}
	allowLoopbackHTTP := !strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production")
	for _, item := range strings.Split(configured, ",") {
		if canonical := canonicalCORSOrigin(item, allowLoopbackHTTP); canonical != "" {
			origins[canonical] = struct{}{}
		}
	}
	return origins
}
