package services

import "testing"

func TestLoadPolarConfigFromEnvMapsCanonicalProducts(t *testing.T) {
	t.Setenv("POLAR_ENVIRONMENT", "sandbox")
	t.Setenv("POLAR_ACCESS_TOKEN", "test-token")
	t.Setenv("POLAR_WEBHOOK_SECRET", "polar_whs_test")
	t.Setenv("POLAR_PRODUCT_STARTER_ID", "prod_starter")
	t.Setenv("POLAR_PRODUCT_PROFESSIONAL_ID", "prod_professional")
	t.Setenv("POLAR_PRODUCT_ENTERPRISE_ID", "prod_enterprise")
	t.Setenv("POLAR_SUCCESS_URL", "https://tradepigloball.co/account?billing=success")
	t.Setenv("POLAR_RETURN_URL", "http://unsafe.example.test/return")

	cfg := LoadPolarConfigFromEnv()
	if cfg.Environment != "sandbox" || cfg.APIBaseURL != polarSandboxAPIBase {
		t.Fatalf("unexpected sandbox config: %#v", cfg)
	}
	if got := cfg.ProductID("professional"); got != "prod_professional" {
		t.Fatalf("professional product = %q", got)
	}
	if got := cfg.PlanForProduct("prod_enterprise"); got != "enterprise" {
		t.Fatalf("enterprise plan mapping = %q", got)
	}
	if !cfg.CheckoutConfigured("starter") || !cfg.WebhookConfigured() {
		t.Fatal("expected configured sandbox billing")
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
	t.Setenv("POLAR_PRODUCT_STARTER_ID", "prod_starter")

	cfg := LoadPolarConfigFromEnv()
	if cfg.CheckoutConfigured("starter") || cfg.WebhookConfigured() {
		t.Fatalf("unknown environment must fail closed: %#v", cfg)
	}
}
