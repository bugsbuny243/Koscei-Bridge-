package main

import (
	"os"
	"strings"
	"testing"
)

func readSurfaceV3(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(body)
}

func TestCustomerSurfaceV3KeepsOneSimpleNavigationAndScanEntry(t *testing.T) {
	product := readSurfaceV3(t, "public/js/koschei-product-v2.js")
	for _, required := range []string{
		"['/','Home']",
		"['/scan','Scan']",
		"['/reports','Activity']",
		"['/dashboard','Workspace']",
		"['/pricing','Plans']",
		"customer-mobile-nav-v3",
		"customer-scan-flow-v3.js",
		"customer-result-guidance-v3.js",
		"customer-workspace-plans-v3.js",
	} {
		if !strings.Contains(product, required) {
			t.Fatalf("customer product shell missing %q", required)
		}
	}

	scan := readSurfaceV3(t, "public/js/customer-scan-flow-v3.js")
	for _, required := range []string{
		"Advanced scan options",
		"Target type override",
		"Site URL detected",
		"Serialized Solana transaction detected",
		"Solana address detected",
		"Ambiguous Solana addresses stay explicit",
	} {
		if !strings.Contains(scan, required) {
			t.Fatalf("customer scan flow missing %q", required)
		}
	}
	if strings.Contains(scan, "fetch(") {
		t.Fatal("customer scan presentation must not create a parallel evidence/API decision path")
	}
}

func TestCustomerResultGuidanceV3UsesCanonicalPolicyAndThreatPresentationOnly(t *testing.T) {
	guidance := readSurfaceV3(t, "public/js/customer-result-guidance-v3.js")
	for _, required := range []string{
		".customer-result-action",
		"threat_anticipation",
		"watch_signals",
		"koschei:customer-premium-mounted",
		"WHAT COULD HAPPEN",
		"WHAT TO WATCH",
		"WHAT TO DO NOW",
		"No deterministic blocking rule fired",
		"Koschei cannot establish a safe decision path",
	} {
		if !strings.Contains(guidance, required) {
			t.Fatalf("customer result guidance missing %q", required)
		}
	}
	for _, forbidden := range []string{"risk_index", "risk score", "Math.round", "Math.random", "fetch("} {
		if strings.Contains(guidance, forbidden) {
			t.Fatalf("customer result guidance must not calculate or fetch decision truth: found %q", forbidden)
		}
	}
}

func TestWorkspaceV3UsesSaaSEntitlementNotTokenHoldings(t *testing.T) {
	workspace := readSurfaceV3(t, "public/js/customer-workspace-plans-v3.js")
	for _, required := range []string{
		"/api/auth/premium-access",
		"starter",
		"professional",
		"enterprise",
		"Plans change capacity and eligible operational surfaces",
	} {
		if !strings.Contains(workspace, required) {
			t.Fatalf("workspace plan surface missing %q", required)
		}
	}
	for _, forbidden := range []string{"KOSCH", "token_access_snapshots", "wallet balance"} {
		if strings.Contains(workspace, forbidden) {
			t.Fatalf("workspace commercial access regressed to token authorization: found %q", forbidden)
		}
	}
}

func TestOwnerSurfaceV3SeparatesSaaSCustomersFromTokenTelemetry(t *testing.T) {
	owner := readSurfaceV3(t, "public/js/owner-operations-v3.js")
	for _, required := range []string{
		"/api/owner/users",
		"SaaS plan distribution",
		"Accounts and paid access, without token-tier confusion.",
		"/api/owner/kosch-access",
		"KOSCH is telemetry, not product authorization.",
		"Commercial access is controlled only by active Starter, Professional or Enterprise SaaS entitlements.",
	} {
		if !strings.Contains(owner, required) {
			t.Fatalf("owner v3 surface missing %q", required)
		}
	}
	for _, forbidden := range []string{"KOSCH premium", "KOSCH erişimi", "full Radar"} {
		if strings.Contains(owner, forbidden) {
			t.Fatalf("owner v3 commercial copy regressed to token authorization: found %q", forbidden)
		}
	}
}
