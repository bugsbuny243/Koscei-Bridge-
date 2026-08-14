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

func TestStaticRouteCannotEscapeManifest(t *testing.T) {
	staticDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte("index"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(staticDir), "outside-secret.txt")
	if err := os.WriteFile(outside, []byte("must-not-leak"), 0o644); err != nil {
		t.Fatal(err)
	}

	srv := httptest.NewServer(NewServer(nil, "", "", "", staticDir))
	defer srv.Close()
	client := &http.Client{CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	resp, err := client.Get(srv.URL + "/..%2foutside-secret.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if string(body) == "must-not-leak" {
		t.Fatal("request escaped the trusted static manifest")
	}
}

func TestStaticManifestExcludesSymlinks(t *testing.T) {
	staticDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(staticDir, "index.html"), []byte("index"), 0o644); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(filepath.Dir(staticDir), "symlink-secret.txt")
	if err := os.WriteFile(outside, []byte("must-not-leak"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(staticDir, "linked.txt")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	manifest, err := buildStaticFileManifest(staticDir)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := manifest["linked.txt"]; ok {
		t.Fatal("symlink was admitted to the static manifest")
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
