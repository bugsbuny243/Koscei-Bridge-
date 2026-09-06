package handlers

import "testing"

func TestPremiumAccessUsesSingleProfessionalPaidTier(t *testing.T) {
	for _, value := range []string{"professional", "pro", "builder", "starter", "basic", "enterprise", "studio"} {
		if got := canonicalSaaSPlan(value); got != "professional" {
			t.Fatalf("canonicalSaaSPlan(%q)=%q want=professional", value, got)
		}
		if !planTierAuthorizes(value, "professional") {
			t.Fatalf("%q did not authorize Professional access", value)
		}
	}
}

func TestPremiumAccessDoesNotUseWalletOrHolderLabels(t *testing.T) {
	for _, value := range []string{"holder", "kosch", "token", "whale"} {
		if canonicalSaaSPlan(value) != "" {
			t.Fatalf("%q unexpectedly mapped to a paid SaaS plan", value)
		}
		if planTierAuthorizes(value, "professional") {
			t.Fatalf("%q unexpectedly authorized Professional access", value)
		}
	}
}

func TestPremiumAccessLegacyPackageNamesAreCompatibilityAliasesOnly(t *testing.T) {
	for _, input := range []string{"starter", "basic", "enterprise", "studio", "builder", "pro"} {
		if got := canonicalSaaSPlan(input); got != "professional" {
			t.Fatalf("canonicalSaaSPlan(%q)=%q want=professional", input, got)
		}
	}
}
