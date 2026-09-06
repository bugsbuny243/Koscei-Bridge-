package services

import "testing"

func TestLoadPolarConfigFromEnvUsesOnlyProfessionalCheckoutProduct(t *testing.T) {
	t.Setenv("POLAR_ENVIRONMENT", "sandbox")
	t.Setenv("POLAR_ACCESS_TOKEN", "test-token")
	t.Setenv("POLAR_WEBHOOK_SECRET", "polar_whs_test")
	t.Setenv("POLAR_PRODUCT_PROFESSIONAL_ID", "prod_professional")
	t.Setenv("POLAR_SUCCESS_URL", "https://tradepigloball.co/account?billing=success")
	t.Setenv("POLAR_RETURN_URL", "http://unsafe.example.test/return")

	cfg := LoadPolarConfigFromEnv()
	if cfg.Environment != "sandbox" || cfg.APIBaseURL != polarSandboxAPIBase {
		t.Fatalf("unexpected sandbox config: %#v", cfg)
	}
	if got := cfg.ProductID("professional"); got != "prod_professional" {
		t.Fatalf("professional product = %q", got)
	}
	for _, removed := range []string{"starter", "enterprise", "pro", "studio"} {
		if got := cfg.ProductID(removed); got != "" {
			t.Fatalf("removed plan %q unexpectedly sellable: %q", removed, got)
		}
	}
	if got := cfg.PlanForProduct("prod_professional"); got != "professional" {
		t.Fatalf("Professional product plan mapping = %q", got)
	}
	if got := cfg.PlanForProduct("prod_removed"); got != "" {
		t.Fatalf("unknown product unexpectedly mapped to plan %q", got)
	}
	if !cfg.CheckoutConfigured("professional") || !cfg.WebhookConfigured() {
		t.Fatal("expected configured Professional sandbox billing")
	}
	if cfg.SuccessURL == "" {
		t.Fatal("expected trusted HTTPS success URL")
	}
	if cfg.ReturnURL != "" {
		t.Fatalf("unsafe HTTP return URL was accepted: %q", cfg.ReturnURL)
	}
}

func TestLoadPolarConfigFromEnvFailsClosedOnUnknownEnvironment(t *testing.T) {
	t.Setenv("POLAR_ENVIRONMENT", "staging")
	t.Setenv("POLAR_ACCESS_TOKEN", "token")
	t.Setenv("POLAR_WEBHOOK_SECRET", "secret")
	t.Setenv("POLAR_PRODUCT_PROFESSIONAL_ID", "prod_professional")

	cfg := LoadPolarConfigFromEnv()
	if cfg.CheckoutConfigured("professional") || cfg.WebhookConfigured() {
		t.Fatalf("unknown environment must fail closed: %#v", cfg)
	}
}
