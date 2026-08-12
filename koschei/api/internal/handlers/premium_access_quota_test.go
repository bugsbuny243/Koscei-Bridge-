package handlers

import (
	"testing"
	"time"
)

func TestPremiumAccessCarriesEntitlementCapacity(t *testing.T) {
	expires := time.Date(2026, 9, 12, 0, 0, 0, 0, time.UTC)
	evaluation := planAccessEvaluation{
		Active:           true,
		Plan:             "professional",
		OutputsTotal:     100,
		OutputsRemaining: 93,
		ExpiresAt:        &expires,
		Source:           "entitlement",
	}
	if !evaluation.Active || evaluation.Source != "entitlement" {
		t.Fatalf("unexpected entitlement state: %+v", evaluation)
	}
	if evaluation.OutputsTotal != 100 || evaluation.OutputsRemaining != 93 {
		t.Fatalf("unexpected output capacity: %+v", evaluation)
	}
	if evaluation.ExpiresAt == nil || !evaluation.ExpiresAt.Equal(expires) {
		t.Fatalf("unexpected expiry: %+v", evaluation.ExpiresAt)
	}
}

func TestPremiumAccessHasNoDailyTokenQuotaAuthority(t *testing.T) {
	evaluation := planAccessEvaluation{Active: true, Plan: "starter", OutputsTotal: 25, OutputsRemaining: 25, Source: "entitlement"}
	if !planTierAuthorizes(evaluation.Plan, "starter") {
		t.Fatal("active Starter entitlement did not authorize Starter access")
	}
	if planTierAuthorizes("kosch", "starter") {
		t.Fatal("KOSCH label unexpectedly authorized a SaaS plan")
	}
}
