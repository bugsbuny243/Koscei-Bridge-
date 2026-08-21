package http

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestOwnerStaticRouteServesLoginUI(t *testing.T) {
	staticDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte("index"), 0o644); err != nil {
		t.Fatalf("write index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(staticDir, "owner.html"), []byte("owner panel"), 0o644); err != nil {
		t.Fatalf("write owner: %v", err)
	}
	t.Setenv("OWNER_SECRET", "test-secret")
	t.Setenv("OWNER_WALLET", "")

	srv := httptest.NewServer(NewServer(nil, "", "", "", staticDir))
	t.Cleanup(srv.Close)

	ownerPage, err := http.Get(srv.URL + "/owner")
	if err != nil {
		t.Fatalf("get owner page: %v", err)
	}
	defer ownerPage.Body.Close()
	if ownerPage.StatusCode != http.StatusOK {
		t.Fatalf("GET /owner = %d, want %d", ownerPage.StatusCode, http.StatusOK)
	}

	apiResp, err := http.Get(srv.URL + "/api/owner/status")
	if err != nil {
		t.Fatalf("get owner api without secret: %v", err)
	}
	defer apiResp.Body.Close()
	if apiResp.StatusCode == http.StatusOK {
		t.Fatalf("GET /api/owner/status without secret = %d, want a protected non-OK response", apiResp.StatusCode)
	}
}

func TestCleanRoutesExposeAllPublicModules(t *testing.T) {
	staticDir := t.TempDir()
	files := map[string]string{
		"index.html":             "index",
		"jarvis.html":            "jarvis",
		"account.html":           "account",
		"agent-api.html":         "agent-api",
		"airdrop-checker.html":   "airdrop",
		"chains.html":            "chains",
		"cross-chain-risk.html":  "cross-chain-risk",
		"dashboard.html":         "dashboard",
		"docs.html":              "docs",
		"docs-api.html":          "docs-api",
		"docs-sdk.html":          "docs-sdk",
		"funding-assistant.html": "funding-assistant",
		"hub.html":               "hub",
		"impact.html":            "impact",
		"launches.html":          "launches",
		"login.html":             "login",
		"metadata.html":          "metadata",
		"mev-shield.html":        "mev-shield",
		"owner.html":             "owner",
		"pay-per-tool.html":      "pay-per-tool",
		"pricing.html":           "pricing",
		"program-scanner.html":   "program",
		"radar.html":             "radar",
		"register.html":          "register",
		"reports.html":           "reports",
		"smart-money.html":       "smart-money",
		"support.html":           "support",
		"watchlist.html":         "watchlist",
	}
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(staticDir, name), []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
	}

	srv := httptest.NewServer(NewServer(nil, "", "", "", staticDir))
	t.Cleanup(srv.Close)

	cases := map[string]string{
		"/account":           "account",
		"/agent-api":         "agent-api",
		"/airdrop-checker":   "dashboard",
		"/chains":            "chains",
		"/cross-chain-risk":  "dashboard",
		"/dashboard":         "dashboard",
		"/docs":              "docs",
		"/docs/api":          "docs-api",
		"/docs/sdk":          "docs-sdk",
		"/funding-assistant": "dashboard",
		"/graph":             "dashboard",
		"/hub":               "dashboard",
		"/impact":            "impact",
		"/launches":          "launches",
		"/login":             "login",
		"/metadata":          "metadata",
		"/mev-shield":        "dashboard",
		"/pay-per-tool":      "pay-per-tool",
		"/portfolio":         "dashboard",
		"/pricing":           "pricing",
		"/program-scanner":   "dashboard",
		"/project-radar":     "dashboard",
		"/radar":             "dashboard",
		"/register":          "register",
		"/risk":              "dashboard",
		"/risk-v2":           "dashboard",
		"/smart-money":       "dashboard",
		"/support":           "support",
		"/tools":             "dashboard",
		"/sybil-check":       "dashboard",
		"/token-scanner":     "dashboard",
		"/tx-decoder":        "dashboard",
		"/tx-decoder-pro":    "dashboard",
		"/wallet-score":      "dashboard",
		"/watchlist":         "watchlist",
	}
	for route, want := range cases {
		route, want := route, want
		t.Run(route, func(t *testing.T) {
			resp, err := http.Get(srv.URL + route)
			if err != nil {
				t.Fatalf("get %s: %v", route, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusOK {
				t.Fatalf("GET %s = %d, want %d", route, resp.StatusCode, http.StatusOK)
			}
			body, err := io.ReadAll(resp.Body)
			if err != nil {
				t.Fatalf("read %s: %v", route, err)
			}
			if string(body) != want {
				t.Fatalf("GET %s body = %q, want %q", route, string(body), want)
			}
		})
	}
}

func TestLegacyRedirectHTMLRoutesAreOwnedByRouter(t *testing.T) {
	staticDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte("index"), 0o644); err != nil {
		t.Fatalf("write index: %v", err)
	}
	if err := os.WriteFile(filepath.Join(staticDir, "dashboard.html"), []byte("dashboard"), 0o644); err != nil {
		t.Fatalf("write dashboard: %v", err)
	}

	// Deliberately do not create the legacy .html tombstone files. These URLs
	// must remain compatible because the Go router owns them, not because the
	// FileServer happens to find a stale asset on disk.
	srv := httptest.NewServer(NewServer(nil, "", "", "", staticDir))
	t.Cleanup(srv.Close)
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }}

	routes := []string{
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
	}
	for _, route := range routes {
		route := route
		t.Run(route, func(t *testing.T) {
			resp, err := client.Get(srv.URL + route)
			if err != nil {
				t.Fatalf("get %s: %v", route, err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != http.StatusPermanentRedirect {
				t.Fatalf("GET %s = %d, want %d", route, resp.StatusCode, http.StatusPermanentRedirect)
			}
			if got := resp.Header.Get("Location"); got != "/dashboard" {
				t.Fatalf("GET %s Location = %q, want /dashboard", route, got)
			}
		})
	}
}
