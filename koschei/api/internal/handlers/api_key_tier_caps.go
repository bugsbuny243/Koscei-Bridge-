package handlers

import "strings"

const (
	defaultAPIKeyMonthlyLimit = 1000
	defaultAPIKeyRPM          = 60
)

type apiKeyTierCaps struct {
	MaxMonthly int
	MaxRPM     int
}

var apiKeyCapsByTier = map[string]apiKeyTierCaps{
	"starter":      {MaxMonthly: 1000, MaxRPM: 30},
	"professional": {MaxMonthly: 20000, MaxRPM: 120},
	"enterprise":   {MaxMonthly: 200000, MaxRPM: 600},
}

func apiKeyEffectiveTier(evaluation planAccessEvaluation, evaluationErr error) string {
	if evaluationErr != nil || !evaluation.Active {
		return "none"
	}
	plan := normalizePackageID(strings.ToLower(strings.TrimSpace(evaluation.Plan)))
	if planTierRank(plan) == 0 {
		return "none"
	}
	if _, ok := apiKeyCapsByTier[plan]; !ok {
		return "none"
	}
	return plan
}

func apiKeyCapsForTier(tier string) apiKeyTierCaps {
	plan := normalizePackageID(strings.ToLower(strings.TrimSpace(tier)))
	if caps, ok := apiKeyCapsByTier[plan]; ok {
		return caps
	}
	return apiKeyCapsByTier["starter"]
}

func clampAPIKeyLimits(requestedMonthly, requestedRPM int, caps apiKeyTierCaps) (int, int) {
	monthly := requestedMonthly
	if monthly <= 0 {
		monthly = defaultAPIKeyMonthlyLimit
	}
	rpm := requestedRPM
	if rpm <= 0 {
		rpm = defaultAPIKeyRPM
	}
	if monthly > caps.MaxMonthly {
		monthly = caps.MaxMonthly
	}
	if rpm > caps.MaxRPM {
		rpm = caps.MaxRPM
	}
	return monthly, rpm
}

// APIKeyAuth avoids re-running billing authorization on every request. Route
// authorization binds the owning API key to an active Enterprise entitlement;
// these caps remain an absolute server-side ceiling for stored key limits.
func clampAPIPrincipalToAbsoluteCaps(p apiPrincipal) apiPrincipal {
	caps := apiKeyCapsByTier["enterprise"]
	p.MonthlyLimit, p.RateLimitPerMinute = clampAPIKeyLimits(p.MonthlyLimit, p.RateLimitPerMinute, caps)
	return p
}
