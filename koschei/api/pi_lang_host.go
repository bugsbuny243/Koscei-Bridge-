package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const piLangProductionHost = "koschei-web3-hub-production.up.railway.app"

// piLangHostSurface gives Koschei Lang its own root-domain surface on the
// Railway service domain without changing tradepigloball.co or its existing
// Pi validation file. Pi requires an app URL with no path component, so the
// same Go service dispatches by Host instead of creating another service.
func piLangHostSurface(next http.Handler, staticDir string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !isPiLangHost(r.Host) {
			next.ServeHTTP(w, r)
			return
		}

		switch r.URL.Path {
		case "/", "/index.html":
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			w.Header().Set("Cache-Control", "no-store")
			http.ServeFile(w, r, filepath.Join(staticDir, "lang.html"))
			return
		case "/validation-key.txt":
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.WriteHeader(http.StatusMethodNotAllowed)
				return
			}
			key := strings.TrimSpace(os.Getenv("PI_LANG_VALIDATION_KEY"))
			if key == "" {
				http.Error(w, "Pi Lang validation key is not configured", http.StatusServiceUnavailable)
				return
			}
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			if r.Method == http.MethodHead {
				w.WriteHeader(http.StatusOK)
				return
			}
			_, _ = w.Write([]byte(key + "\n"))
			return
		default:
			next.ServeHTTP(w, r)
		}
	})
}

func isPiLangHost(hostport string) bool {
	host := strings.ToLower(strings.TrimSpace(hostport))
	if i := strings.IndexByte(host, ':'); i >= 0 {
		host = host[:i]
	}
	return host == piLangProductionHost
}
