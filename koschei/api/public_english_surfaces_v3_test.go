package main

import (
	"os"
	"strings"
	"testing"
)

func TestPrimaryPublicSurfacesAreSourceEnglish(t *testing.T) {
	files := []string{
		"public/owner-production.html",
		"public/scan.html",
		"public/dashboard.html",
	}
	for _, path := range files {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("read %s: %v", path, err)
		}
		text := string(body)
		if !strings.Contains(text, `<html lang="en">`) {
			t.Errorf("%s is not source-English", path)
		}
		for _, forbidden := range []string{
			"Veriyi yenile",
			"Tam Radar",
			"Taramayı Başlat",
			"Token Tara",
			"Ana Sayfa",
			"Kontrol ediliyor",
			"Giriş",
			"Çıkış",
			"public-solana-scan-tr.js",
		} {
			if strings.Contains(text, forbidden) {
				t.Errorf("%s still contains Turkish product copy %q", path, forbidden)
			}
		}
	}
}

func TestCanonicalInvestigationSurfaceMountsProfessionalModesAndEvidenceControllers(t *testing.T) {
	body, err := os.ReadFile("public/scan.html")
	if err != nil {
		t.Fatalf("read canonical investigation page: %v", err)
	}
	text := string(body)
	for _, required := range []string{
		"PROFESSIONAL · CLASSIC INVESTIGATION CONSOLE",
		"Descend into the evidence.",
		"Free Quick Check execution has been removed",
		"data-scan-mode=\"token\"",
		"data-scan-mode=\"transaction\"",
		"data-scan-mode=\"deep\"",
		"arvis-premium-contract.js",
		"customer-arvis-premium-suite.js",
		"data-customer-arvis-result",
		"public-solana-scan.js?v=12",
		"Missing evidence is shown as a limitation, not converted into a safety claim.",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("canonical investigation page missing %q", required)
		}
	}
	for _, forbidden := range []string{`data-scan-mode="quick"`, `href="/safe-check"`, `href="/transaction-shield"`, `href="/security-radar"`} {
		if strings.Contains(text, forbidden) {
			t.Errorf("canonical investigation page contains retired or duplicate scanner contract %q", forbidden)
		}
	}
}

func TestDashboardIsSingleCustomerSecurityPanel(t *testing.T) {
	body, err := os.ReadFile("public/dashboard.html")
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}
	text := string(body)
	for _, required := range []string{
		"Koschei Web3 | Customer Panel",
		"Security Overview",
		"ARVIS intelligence map",
		"Live operational truth",
		"No fake telemetry",
		"Authenticated session",
		"Durable history",
		"Continuous monitoring",
		"Persisted alerts",
		"Feedback storage",
		"PERSISTENCE OFF",
		"Production truth only.",
		"Solana is the live chain core.",
		"NOT LIVE",
		"/css/koschei-dashboard.css?v=2",
		"/js/customer-workspace-v2.js?v=3",
		"/js/koschei-dashboard.js?v=4",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("dashboard missing customer panel contract %q", required)
		}
	}
	if got := strings.Count(text, `<link rel="stylesheet"`); got != 1 {
		t.Errorf("dashboard must load exactly one stylesheet, got %d", got)
	}
	for _, forbidden := range []string{
		`id="mint"`,
		`id="scan"`,
		`id="exposureForm"`,
		`id="feedbackForm"`,
		"/api/token/scan",
		"data-customer-arvis-result",
		"Signed report vault",
		"RECENT CANONICAL INVESTIGATION",
		"RECENT MONITORING ALERTS",
		"Report a gap",
		"koschei.css",
		"customer-command-center-v1.css",
		"customer-command-universe-v2.css",
		"koschei-global-shell.js",
		"koschei-product-v2.js",
		"KOSCH Premium",
		"KOSCH holder",
	} {
		if strings.Contains(text, forbidden) {
			t.Errorf("dashboard contains duplicate, legacy or overstated surface %q", forbidden)
		}
	}
}

func TestUnifiedScanBehaviorKeepsRealLegacyEndpointsWithoutExposingQuickModeUI(t *testing.T) {
	body, err := os.ReadFile("public/js/public-solana-scan.js")
	if err != nil {
		t.Fatalf("read unified scan behavior: %v", err)
	}
	text := string(body)
	for _, required := range []string{
		"/api/arvis/preflight",
		"/api/token/scan",
		"/api/public/transaction-simulate",
		"Quick Check",
		"Token Investigation",
		"Simulate Transaction",
		"Deep Radar",
		"Missing evidence = no safety decision",
		"window.__koscheiUnifiedScanNavigation",
		"script.src='/js/unified-scan-navigation.js?v=1'",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("unified scan behavior missing %q", required)
		}
	}
}
