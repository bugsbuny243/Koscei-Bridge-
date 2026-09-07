package main

import (
	"errors"
	"os"
	"strings"
	"testing"
)

func TestRetiredDangerousHandlersStayRemoved(t *testing.T) {
	retired := []string{
		"internal/handlers/mev_shield.go",
		"internal/handlers/liquidity_radar.go",
		"internal/handlers/dao_guardian.go",
		"internal/handlers/owner_payment_health.go",
		"internal/handlers/jobs.go",
		"internal/handlers/metadata.go",
		"internal/handlers/plans.go",
		"internal/handlers/credits.go",
		"internal/handlers/entitlement.go",
	}
	for _, path := range retired {
		if _, err := os.Stat(path); err == nil {
			t.Errorf("retired handler returned: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat %s: %v", path, err)
		}
	}
}

func TestStandaloneCustomerAndStaleProductPagesStayRetired(t *testing.T) {
	for _, path := range []string{
		"public/feedback.html",
		"public/exposure-report.html",
		"public/security-ecosystem.html",
		"public/token-vesting.html",
	} {
		if _, err := os.Stat(path); err == nil {
			t.Errorf("retired standalone surface returned: %s", path)
		} else if !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("stat %s: %v", path, err)
		}
	}
}

func TestCustomerPanelExposesOnlyLiveRuntimeControls(t *testing.T) {
	html, err := os.ReadFile("public/dashboard.html")
	if err != nil {
		t.Fatalf("read dashboard: %v", err)
	}
	workspace, err := os.ReadFile("public/js/customer-workspace-v2.js")
	if err != nil {
		t.Fatalf("read customer workspace: %v", err)
	}
	js, err := os.ReadFile("public/js/koschei-dashboard.js")
	if err != nil {
		t.Fatalf("read dashboard runtime: %v", err)
	}

	htmlText := string(html)
	for _, required := range []string{
		`id="feedback"`,
		`id="feedbackForm"`,
		"intentionally stateless",
		"PERSISTENCE OFF",
		"Koschei analyzes and simulates. It does not sign, submit, relay or broadcast customer transactions.",
	} {
		if !strings.Contains(htmlText, required) {
			t.Errorf("dashboard missing runtime-truth contract %q", required)
		}
	}
	for _, forbidden := range []string{`id="exposureForm"`, "KOSCH holder", "Free Safe Check", "KOSCH Premium"} {
		if strings.Contains(htmlText, forbidden) {
			t.Errorf("dashboard contains retired/non-live product control %q", forbidden)
		}
	}

	workspaceText := string(workspace)
	if !strings.Contains(workspaceText, "read('/api/me')") {
		t.Error("workspace missing stateless authenticated identity source")
	}
	for _, forbidden := range []string{
		"/api/auth/premium-access",
		"/api/v1/radar/jobs/",
		"/api/watchlist",
		"/api/watchlist/alerts",
		"/api/v1/radar/exposure",
	} {
		if strings.Contains(workspaceText, forbidden) {
			t.Errorf("workspace calls persistence-backed route in stateless production %q", forbidden)
		}
	}

	jsText := string(js)
	for _, required := range []string{
		"/api/analytics/event",
		"feedbackContainsSecretLanguage",
	} {
		if !strings.Contains(jsText, required) {
			t.Errorf("dashboard runtime missing live backend contract %q", required)
		}
	}
	for _, forbidden := range []string{"/api/v1/radar/exposure", "sendBundle", "JITO_BUNDLE_URL", "Math.random("} {
		if strings.Contains(jsText, forbidden) {
			t.Errorf("dashboard runtime contains forbidden/non-live behavior %q", forbidden)
		}
	}
}