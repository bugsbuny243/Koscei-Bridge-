package handlers

import "testing"

func TestPremiumAccessPlanHierarchyStartsAtStarter(t *testing.T) {
	if !planTierAuthorizes("starter", "starter") {
		t.Fatal("starter entitlement did not authorize starter access")
	}
	if !planTierAuthorizes("professional", "starter") {
		t.Fatal("professional entitlement did not inherit starter access")
	}
	if !planTierAuthorizes("enterprise", "starter") {
		t.Fatal("enterprise entitlement did not inherit starter access")
	}
}

func TestPremiumAccessDoesNotUseWalletOrHolderLabels(t *testing.T) {
	for _, value := range []string{"holder", "kosch", "token", "whale"} {
		if canonicalSaaSPlan(value) != "" {
			t.Fatalf("%q unexpectedly mapped to a paid SaaS plan", value)
		}
		if planTierAuthorizes(value, "starter") {
			t.Fatalf("%q unexpectedly authorized Starter access", value)
		}
	}
}

func TestPremiumAccessLegacyPlanAliasesRemainBillingOnly(t *testing.T) {
	cases := map[string]string{
		"basic":  "starter",
		"pro":    "professional",
		"studio": "enterprise",
	}
	for input, want := range cases {
		if got := canonicalSaaSPlan(input); got != want {
			t.Fatalf("canonicalSaaSPlan(%q)=%q want=%q", input, got, want)
		}
	}
}
