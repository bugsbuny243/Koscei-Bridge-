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

func TestDashboardIsARVISProfessionalSecurityWorkspace(t *testing.T) {
	body, err := os.ReadFile("public/dashboard.html")
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}
	text := string(body)
	for _, required := range []string{
		"Professional Security Command Center",
		"PROFESSIONAL · ARVIS COMMAND UNIVERSE",
		"Investigate. Correlate. Prove.",
		"ARVIS Investigation",
		"Investigation History",
		"Monitoring & developer access",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("dashboard missing workspace contract %q", required)
		}
	}
	for _, forbidden := range []string{`id="mint"`, `id="scan"`, "/api/token/scan", "data-customer-arvis-result", "Signed report vault"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("dashboard contains duplicate or overstated scan/report behavior %q", forbidden)
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
