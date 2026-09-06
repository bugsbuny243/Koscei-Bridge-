package handlers

const (
	defaultAPIKeyMonthlyLimit = 1000
	defaultAPIKeyRPM          = 60
)

type apiKeyTierCaps struct {
	MaxMonthly int
	MaxRPM     int
}

// Koschei exposes one paid SaaS entitlement: Professional.
var apiKeyCapsByTier = map[string]apiKeyTierCaps{
	"professional": {MaxMonthly: 20000, MaxRPM: 120},
}

func apiKeyEffectiveTier(evaluation planAccessEvaluation, evaluationErr error) string {
	if evaluationErr != nil || !evaluation.Active {
		return "none"
	}
	plan := canonicalSaaSPlan(evaluation.Plan)
	if plan != "professional" {
		return "none"
	}
	return "professional"
}

func apiKeyCapsForTier(tier string) apiKeyTierCaps {
	if canonicalSaaSPlan(tier) != "professional" {
		return apiKeyTierCaps{}
	}
	return apiKeyCapsByTier["professional"]
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
// authorization binds the owning API key to an active Professional entitlement;
// these caps remain an absolute server-side ceiling for stored key limits.
func clampAPIPrincipalToAbsoluteCaps(p apiPrincipal) apiPrincipal {
	caps := apiKeyCapsByTier["professional"]
	p.MonthlyLimit, p.RateLimitPerMinute = clampAPIKeyLimits(p.MonthlyLimit, p.RateLimitPerMinute, caps)
	return p
}
