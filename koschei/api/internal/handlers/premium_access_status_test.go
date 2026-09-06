package handlers

import "testing"

func TestPremiumAccessUsesOnlyProfessionalPaidTier(t *testing.T) {
	if got := canonicalSaaSPlan("professional"); got != "professional" {
		t.Fatalf("canonicalSaaSPlan(professional)=%q want=professional", got)
	}
	if !planTierAuthorizes("professional", "professional") {
		t.Fatal("Professional did not authorize Professional access")
	}
}

func TestPremiumAccessRejectsRemovedAndNonCommercialPlanLabels(t *testing.T) {
	for _, value := range []string{"starter", "basic", "builder", "pro", "enterprise", "studio", "holder", "kosch", "token", "whale"} {
		if got := canonicalSaaSPlan(value); got != "" {
			t.Fatalf("canonicalSaaSPlan(%q)=%q want empty", value, got)
		}
		if planTierAuthorizes(value, "professional") {
			t.Fatalf("%q unexpectedly authorized Professional access", value)
		}
	}
}
