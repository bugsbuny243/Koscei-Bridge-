package handlers

import (
	"errors"
	"testing"
)

func TestAPIKeyEffectiveTierUsesSingleProfessionalPlan(t *testing.T) {
	cases := []struct {
		name string
		eval planAccessEvaluation
		err  error
		want string
	}{
		{name: "legacy starter", eval: planAccessEvaluation{Active: true, Plan: "starter"}, want: "professional"},
		{name: "professional alias", eval: planAccessEvaluation{Active: true, Plan: "pro"}, want: "professional"},
		{name: "legacy enterprise", eval: planAccessEvaluation{Active: true, Plan: "enterprise"}, want: "professional"},
		{name: "inactive", eval: planAccessEvaluation{Active: false, Plan: "enterprise"}, want: "none"},
		{name: "lookup failure", eval: planAccessEvaluation{Active: true, Plan: "enterprise"}, err: errors.New("db unavailable"), want: "none"},
		{name: "unknown", eval: planAccessEvaluation{Active: true, Plan: "holder"}, want: "none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := apiKeyEffectiveTier(tc.eval, tc.err); got != tc.want {
				t.Fatalf("apiKeyEffectiveTier()=%q want=%q", got, tc.want)
			}
		})
	}
}

func TestAPIKeyPlanCapsNormalizeHistoricalPaidPlansToProfessional(t *testing.T) {
	for _, tier := range []string{"starter", "basic", "professional", "pro", "enterprise", "studio"} {
		if got := apiKeyCapsForTier(tier); got.MaxMonthly != 20000 || got.MaxRPM != 120 {
			t.Fatalf("%s caps=%#v", tier, got)
		}
	}
}

func TestAPIKeyDefaultsRemainSubjectToProfessionalCaps(t *testing.T) {
	monthly, rpm := clampAPIKeyLimits(0, 0, apiKeyCapsByTier["professional"])
	if monthly != defaultAPIKeyMonthlyLimit || rpm != defaultAPIKeyRPM {
		t.Fatalf("professional defaults after clamp = %d/%d", monthly, rpm)
	}
}

func TestAPIKeyUnknownTierFallsBackToProfessionalCeiling(t *testing.T) {
	got := apiKeyCapsForTier("unknown")
	if got.MaxMonthly != 20000 || got.MaxRPM != 120 {
		t.Fatalf("unknown fallback caps=%#v", got)
	}
}

func TestAPIKeyAuthAbsoluteCeilingProtectsExistingRows(t *testing.T) {
	principal := clampAPIPrincipalToAbsoluteCaps(apiPrincipal{
		MonthlyLimit:       999999999,
		RateLimitPerMinute: 999999999,
	})
	if principal.MonthlyLimit != 20000 || principal.RateLimitPerMinute != 120 {
		t.Fatalf("absolute clamp = %#v", principal)
	}
}
