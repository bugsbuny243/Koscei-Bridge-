package main

import (
	"os"
	"strings"
	"testing"
)

func TestCommercialReadinessCustomerSurfaces(t *testing.T) {
	pricing := mustReadCommercialSurface(t, "public/pricing.html")
	for _, required := range []string{
		"ONE ACCESS CONTRACT · PROFESSIONAL",
		"Enter the ARVIS universe.",
		`data-polar-plan="professional"`,
		"Professional is the only paid customer plan.",
		"The server decides access. The browser never invents it.",
		"polar-checkout-v1.js",
	} {
		if !strings.Contains(pricing, required) {
			t.Errorf("pricing missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"COMMERCIAL CHECKOUT PAUSED",
		"Evidence first. Paid checkout later.",
		`id="earlyAccessForm"`,
		"<h2>Free Core</h2>",
		"$299 / month",
		"$999 / month",
		"$4,999 / month",
	} {
		if strings.Contains(pricing, forbidden) {
			t.Errorf("pricing still exposes retired commercial surface %q", forbidden)
		}
	}

	reports := mustReadCommercialSurface(t, "public/js/customer-reports-v2.js")
	for _, required := range []string{
		"function historyAccessError(statusCode)",
		"Sign in to view your investigation history.",
		"Investigation history requires an active Professional entitlement.",
	} {
		if !strings.Contains(reports, required) {
			t.Errorf("reports error boundary missing %q", required)
		}
	}
	if strings.Contains(reports, "access+text(data?.message||data?.error") {
		t.Error("reports still concatenates backend machine errors into customer access copy")
	}

	navigation := mustReadCommercialSurface(t, "public/js/unified-scan-navigation.js")
	if !strings.Contains(navigation, ".customer-sidebar__nav,.customer-command-palette") {
		t.Error("scan navigation does not protect mode-specific customer navigation")
	}
	if !strings.Contains(navigation, "group.matches(protectedCustomerNavSelector)") {
		t.Error("scan navigation does not exclude the customer sidebar from scan-link collapse")
	}

	workspaceCSS := mustReadCommercialSurface(t, "public/css/customer-workspace-v2.css")
	if !strings.Contains(workspaceCSS, ".koschei-safety-strip{display:none!important}") {
		t.Error("dashboard self-promo strip is not suppressed from the customer workspace")
	}

	universeCSS := mustReadCommercialSurface(t, "public/css/koschei-universe-v1.css")
	for _, required := range []string{"body.koschei-universe", ".universe-entry", ".professional-lock"} {
		if !strings.Contains(universeCSS, required) {
			t.Errorf("universe visual system missing %q", required)
		}
	}
}

func mustReadCommercialSurface(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}
