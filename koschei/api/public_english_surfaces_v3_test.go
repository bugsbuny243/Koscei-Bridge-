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

func TestCanonicalScanCenterMountsCompleteARVISAndAllModes(t *testing.T) {
	body, err := os.ReadFile("public/scan.html")
	if err != nil {
		t.Fatalf("read canonical scan page: %v", err)
	}
	text := string(body)
	for _, required := range []string{
		"Unified Scan Center",
		"data-scan-mode=\"quick\"",
		"data-scan-mode=\"token\"",
		"data-scan-mode=\"transaction\"",
		"data-scan-mode=\"deep\"",
		"arvis-premium-contract.js",
		"customer-arvis-premium-suite.js",
		"data-customer-arvis-result",
		"public-solana-scan.js?v=11",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("canonical scan page missing %q", required)
		}
	}
	for _, forbidden := range []string{`href="/safe-check"`, `href="/transaction-shield"`, `href="/security-radar"`} {
		if strings.Contains(text, forbidden) {
			t.Errorf("canonical scan page still links to duplicate scanner %q", forbidden)
		}
	}
}

func TestDashboardIsWorkspaceNotAnotherScanner(t *testing.T) {
	body, err := os.ReadFile("public/dashboard.html")
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}
	text := string(body)
	for _, required := range []string{"Workspace, not another scanner", "Open Scan Center", "Report vault", "Monitoring and integration"} {
		if !strings.Contains(text, required) {
			t.Errorf("dashboard missing workspace contract %q", required)
		}
	}
	for _, forbidden := range []string{`id="mint"`, `id="scan"`, "/api/token/scan", "data-customer-arvis-result"} {
		if strings.Contains(text, forbidden) {
			t.Errorf("dashboard still contains duplicate scan behavior %q", forbidden)
		}
	}
}

func TestUnifiedScanBehaviorUsesRealModeEndpoints(t *testing.T) {
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
		"Transaction Simulation",
		"Deep Radar",
		"Missing evidence = no safety decision",
	} {
		if !strings.Contains(text, required) {
			t.Errorf("unified scan behavior missing %q", required)
		}
	}
}
