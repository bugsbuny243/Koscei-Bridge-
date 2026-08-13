package handlers

import (
	"errors"
	"testing"
)

func TestAPIKeyEffectiveTierUsesActiveSaaSPlan(t *testing.T) {
	cases := []struct {
		name string
		eval planAccessEvaluation
		err  error
		want string
	}{
		{name: "starter", eval: planAccessEvaluation{Active: true, Plan: "starter"}, want: "starter"},
		{name: "professional alias", eval: planAccessEvaluation{Active: true, Plan: "pro"}, want: "professional"},
		{name: "enterprise", eval: planAccessEvaluation{Active: true, Plan: "enterprise"}, want: "enterprise"},
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

func TestAPIKeyPlanCaps(t *testing.T) {
	if got := apiKeyCapsForTier("starter"); got.MaxMonthly != 1000 || got.MaxRPM != 30 {
		t.Fatalf("starter caps=%#v", got)
	}
	if got := apiKeyCapsForTier("pro"); got.MaxMonthly != 20000 || got.MaxRPM != 120 {
		t.Fatalf("professional alias caps=%#v", got)
	}
	if got := apiKeyCapsForTier("enterprise"); got.MaxMonthly != 200000 || got.MaxRPM != 600 {
		t.Fatalf("enterprise caps=%#v", got)
	}
}

func TestAPIKeyDefaultsRemainSubjectToStarterCaps(t *testing.T) {
	monthly, rpm := clampAPIKeyLimits(0, 0, apiKeyCapsByTier["starter"])
	if monthly != 1000 || rpm != 30 {
		t.Fatalf("starter defaults after clamp = %d/%d", monthly, rpm)
	}
}

func TestAPIKeyAuthAbsoluteCeilingProtectsExistingRows(t *testing.T) {
	principal := clampAPIPrincipalToAbsoluteCaps(apiPrincipal{
		MonthlyLimit:       999999999,
		RateLimitPerMinute: 999999999,
	})
	if principal.MonthlyLimit != 200000 || principal.RateLimitPerMinute != 600 {
		t.Fatalf("absolute clamp = %#v", principal)
	}
}
