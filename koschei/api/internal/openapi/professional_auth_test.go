package openapi

import "testing"

func TestProfessionalOnlyAuthSemantics(t *testing.T) {
	for _, path := range []string{
		"/api/arvis/preflight",
		"/api/token/scan",
		"/api/v1/radar/check",
		"/api/v1/radar/jobs",
		"/api/v1/radar/detail",
		"/api/v1/token/extensions",
		"/api/v1/address-poisoning/check",
		"/api/jobs/token-scan",
		"/api/watchlist",
		"/api/webhooks",
		"/api/account/api-keys",
	} {
		if got := authTier(path, "server.go"); got != "customer_session_plus_professional_entitlement" {
			t.Fatalf("authTier(%q)=%q want customer_session_plus_professional_entitlement", path, got)
		}
	}

	for _, path := range []string{
		"/api/v1/scan/token",
		"/api/v1/usage",
		"/api/v1/shield/preflight",
		"/api/v1/shield/transaction",
		"/api/v1/defense/validation",
		"/api/v1/execution-assurance/safe/verify",
	} {
		if got := authTier(path, "server.go"); got != "api_key_plus_professional_entitlement" {
			t.Fatalf("authTier(%q)=%q want api_key_plus_professional_entitlement", path, got)
		}
	}

	secured := security("api_key_plus_professional_entitlement")
	if len(secured) != 1 {
		t.Fatalf("Professional developer API auth has no security scheme: %#v", secured)
	}
}
