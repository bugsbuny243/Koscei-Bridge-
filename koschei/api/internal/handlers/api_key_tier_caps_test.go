package handlers

import (
	"errors"
	"testing"
)

func TestAPIKeyEffectiveTierUsesOnlyProfessionalPlan(t *testing.T) {
	cases := []struct {
		name string
		eval planAccessEvaluation
		err  error
		want string
	}{
		{name: "professional", eval: planAccessEvaluation{Active: true, Plan: "professional"}, want: "professional"},
		{name: "removed starter", eval: planAccessEvaluation{Active: true, Plan: "starter"}, want: "none"},
		{name: "removed pro alias", eval: planAccessEvaluation{Active: true, Plan: "pro"}, want: "none"},
		{name: "removed enterprise", eval: planAccessEvaluation{Active: true, Plan: "enterprise"}, want: "none"},
		{name: "inactive", eval: planAccessEvaluation{Active: false, Plan: "professional"}, want: "none"},
		{name: "lookup failure", eval: planAccessEvaluation{Active: true, Plan: "professional"}, err: errors.New("db unavailable"), want: "none"},
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

func TestAPIKeyPlanCapsExistOnlyForProfessional(t *testing.T) {
	got := apiKeyCapsForTier("professional")
	if got.MaxMonthly != 20000 || got.MaxRPM != 120 {
		t.Fatalf("professional caps=%#v", got)
	}
	for _, removed := range []string{"starter", "basic", "pro", "enterprise", "studio", "unknown"} {
		if got := apiKeyCapsForTier(removed); got.MaxMonthly != 0 || got.MaxRPM != 0 {
			t.Fatalf("removed tier %s caps=%#v", removed, got)
		}
	}
}

func TestAPIKeyDefaultsRemainSubjectToProfessionalCaps(t *testing.T) {
	monthly, rpm := clampAPIKeyLimits(0, 0, apiKeyCapsByTier["professional"])
	if monthly != defaultAPIKeyMonthlyLimit || rpm != defaultAPIKeyRPM {
		t.Fatalf("professional defaults after clamp = %d/%d", monthly, rpm)
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
