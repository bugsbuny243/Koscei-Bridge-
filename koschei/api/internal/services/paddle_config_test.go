package services

import "testing"

func clearPaddleConfigEnv(t *testing.T) {
	t.Helper()
	for _, key := range []string{
		"PADDLE_ENV", "PADDLE_ENVIRONMENT", "PADDLE_MODE",
		"PADDLE_API_KEY", "PADDLE_SECRET_KEY", "PADDLE_API_TOKEN", "PADDLE_TOKEN",
		"PADDLE_CLIENT_TOKEN", "PADDLE_CLIENT_SIDE_TOKEN", "PADDLE_CLIENTSIDE_TOKEN", "PUBLIC_PADDLE_CLIENT_TOKEN", "VITE_PADDLE_CLIENT_TOKEN",
		"PADDLE_WEBHOOK_SECRET", "PADDLE_WEBHOOK_KEY", "PADDLE_WEBHOOK_SECRET_KEY", "PADDLE_NOTIFICATION_SECRET", "PADDLE_ENDPOINT_SECRET",
		"PADDLE_STARTER_PRICE_ID", "PADDLE_STARTER_PRICE_USD_ID", "PADDLE_STARTER_USD_PRICE_ID", "PADDLE_STARTER_MONTHLY_PRICE_ID", "PADDLE_BASIC_PRICE_ID", "PADDLE_PRICE_STARTER_ID", "PADDLE_PRICE_ID_STARTER",
		"PADDLE_PROFESSIONAL_PRICE_ID", "PADDLE_PROFESSIONAL_PRICE_USD_ID", "PADDLE_PROFESSIONAL_USD_PRICE_ID", "PADDLE_PROFESSIONAL_MONTHLY_PRICE_ID", "PADDLE_BUILDER_PRICE_ID", "PADDLE_PRO_PRICE_ID", "PADDLE_PRICE_PROFESSIONAL_ID", "PADDLE_PRICE_PRO_ID", "PADDLE_PRICE_ID_PROFESSIONAL",
		"PADDLE_ENTERPRISE_PRICE_ID", "PADDLE_ENTERPRISE_PRICE_USD_ID", "PADDLE_ENTERPRISE_USD_PRICE_ID", "PADDLE_ENTERPRISE_MONTHLY_PRICE_ID", "PADDLE_STUDIO_PRICE_ID", "PADDLE_PRICE_ENTERPRISE_ID", "PADDLE_PRICE_ID_ENTERPRISE",
		"PADDLE_STARTER_PRODUCT_ID", "PADDLE_PRODUCT_STARTER_ID", "PADDLE_PRODUCT_ID_STARTER", "PADDLE_BASIC_PRODUCT_ID",
		"PADDLE_PROFESSIONAL_PRODUCT_ID", "PADDLE_BUILDER_PRODUCT_ID", "PADDLE_PRO_PRODUCT_ID", "PADDLE_PRODUCT_PROFESSIONAL_ID", "PADDLE_PRODUCT_ID_PROFESSIONAL",
		"PADDLE_ENTERPRISE_PRODUCT_ID", "PADDLE_STUDIO_PRODUCT_ID", "PADDLE_PRODUCT_ENTERPRISE_ID", "PADDLE_PRODUCT_ID_ENTERPRISE",
		"PUBLIC_APP_URL", "APP_URL", "BASE_URL", "PUBLIC_URL", "RAILWAY_STATIC_URL", "RAILWAY_PUBLIC_DOMAIN",
		"PADDLE_CHECKOUT_URL", "PADDLE_DEFAULT_PAYMENT_LINK", "PADDLE_PAYMENT_LINK",
	} {
		t.Setenv(key, "")
	}
}

func TestPaddleConfigCanonicalProductionReady(t *testing.T) {
	clearPaddleConfigEnv(t)
	t.Setenv("PADDLE_API_KEY", "pdl_live_apikey_test")
	t.Setenv("PADDLE_CLIENT_TOKEN", "live_client_test")
	t.Setenv("PADDLE_WEBHOOK_SECRET", "pdl_ntfset_test")
	t.Setenv("PADDLE_STARTER_PRICE_ID", "pri_starter")
	t.Setenv("PADDLE_PROFESSIONAL_PRICE_ID", "pri_professional")
	t.Setenv("PADDLE_ENTERPRISE_PRICE_ID", "pri_enterprise")
	t.Setenv("PUBLIC_APP_URL", "https://tradepigloball.co/")

	cfg := LoadPaddleConfigFromEnv()
	if !cfg.Enabled || !cfg.CheckoutReady || !cfg.AutomationReady || !cfg.AllPlansReady {
		t.Fatalf("expected fully configured Paddle, got %#v", cfg.PublicStatus())
	}
	if cfg.ConfiguredPlanCount != 3 {
		t.Fatalf("configured plan count=%d want=3", cfg.ConfiguredPlanCount)
	}
	if !cfg.ClientTokenConfigured {
		t.Fatal("hosted Paddle.js checkout requires client token")
	}
	if cfg.PublicAppURL != "https://tradepigloball.co" || cfg.CheckoutURL != "https://tradepigloball.co/paddle-checkout" {
		t.Fatalf("unexpected Paddle URLs: app=%q checkout=%q", cfg.PublicAppURL, cfg.CheckoutURL)
	}
	if len(cfg.MissingFields) != 0 {
		t.Fatalf("unexpected missing fields: %#v", cfg.MissingFields)
	}
	if paddleConfigStatus(cfg) != "configured" {
		t.Fatalf("unexpected status: %s", paddleConfigStatus(cfg))
	}
}

func TestPaddleConfigUsesRailwayDomainAndAliases(t *testing.T) {
	clearPaddleConfigEnv(t)
	t.Setenv("PADDLE_API_TOKEN", "pdl_live_apikey_test")
	t.Setenv("PUBLIC_PADDLE_CLIENT_TOKEN", "live_client_test")
	t.Setenv("PADDLE_ENDPOINT_SECRET", "pdl_ntfset_test")
	t.Setenv("PADDLE_PRICE_ID_STARTER", "pri_starter")
	t.Setenv("PADDLE_PRICE_ID_PROFESSIONAL", "pri_professional")
	t.Setenv("PADDLE_PRICE_ID_ENTERPRISE", "pri_enterprise")
	t.Setenv("PADDLE_MODE", "production")
	t.Setenv("RAILWAY_PUBLIC_DOMAIN", "tradepigloball.co")

	cfg := LoadPaddleConfigFromEnv()
	if !cfg.Enabled || !cfg.AllPlansReady {
		t.Fatalf("expected Railway/alias configuration to be ready, got %#v", cfg.PublicStatus())
	}
	if cfg.PublicAppURL != "https://tradepigloball.co" {
		t.Fatalf("unexpected Railway public URL: %q", cfg.PublicAppURL)
	}
	if cfg.CheckoutURL != "https://tradepigloball.co/paddle-checkout" {
		t.Fatalf("unexpected checkout URL: %q", cfg.CheckoutURL)
	}
}

func TestPaddleConfigRequiresClientTokenForHostedCheckout(t *testing.T) {
	clearPaddleConfigEnv(t)
	t.Setenv("PADDLE_API_KEY", "pdl_live_apikey_test")
	t.Setenv("PADDLE_WEBHOOK_SECRET", "pdl_ntfset_test")
	t.Setenv("PADDLE_STARTER_PRICE_ID", "pri_starter")

	cfg := LoadPaddleConfigFromEnv()
	if cfg.CheckoutReady || cfg.Enabled {
		t.Fatalf("hosted checkout must remain disabled without client token: %#v", cfg.PublicStatus())
	}
	if paddleConfigStatus(cfg) != "credentials_ready_client_token_missing" {
		t.Fatalf("unexpected status: %s", paddleConfigStatus(cfg))
	}
}

func TestPaddleConfigKeepsAutomationReadyWithPartialCatalog(t *testing.T) {
	clearPaddleConfigEnv(t)
	t.Setenv("PADDLE_API_KEY", "pdl_live_apikey_test")
	t.Setenv("PADDLE_CLIENT_TOKEN", "live_client_test")
	t.Setenv("PADDLE_WEBHOOK_SECRET", "pdl_ntfset_test")
	t.Setenv("PADDLE_STARTER_PRICE_ID", "pri_starter")
	t.Setenv("PADDLE_PROFESSIONAL_PRICE_ID", "pri_professional")

	cfg := LoadPaddleConfigFromEnv()
	if !cfg.Enabled || !cfg.AutomationReady || cfg.AllPlansReady {
		t.Fatalf("expected automated Paddle with partial catalog, got %#v", cfg.PublicStatus())
	}
	if paddleConfigStatus(cfg) != "configured_partial_catalog" {
		t.Fatalf("unexpected status: %s", paddleConfigStatus(cfg))
	}
}

func TestPaddleConfigDetectsEnvironmentMismatch(t *testing.T) {
	clearPaddleConfigEnv(t)
	t.Setenv("PADDLE_ENV", "production")
	t.Setenv("PADDLE_API_KEY", "pdl_sdbx_apikey_test")
	t.Setenv("PADDLE_CLIENT_TOKEN", "test_client_token")
	t.Setenv("PADDLE_WEBHOOK_SECRET", "pdl_ntfset_test")
	t.Setenv("PADDLE_STARTER_PRICE_ID", "pri_starter")

	cfg := LoadPaddleConfigFromEnv()
	if cfg.CredentialEnvironmentMatch || cfg.Enabled {
		t.Fatalf("environment mismatch must disable Paddle: %#v", cfg.PublicStatus())
	}
	if paddleConfigStatus(cfg) != "environment_mismatch" {
		t.Fatalf("unexpected status: %s", paddleConfigStatus(cfg))
	}
}

func TestPaddleConfigStripsWrappedQuotes(t *testing.T) {
	clearPaddleConfigEnv(t)
	t.Setenv("PADDLE_API_KEY", `"pdl_live_apikey_test"`)
	t.Setenv("PADDLE_CLIENT_TOKEN", `'live_client_test'`)
	t.Setenv("PADDLE_WEBHOOK_SECRET", `'pdl_ntfset_test'`)
	t.Setenv("PADDLE_STARTER_PRICE_ID", `"pri_starter"`)

	cfg := LoadPaddleConfigFromEnv()
	if cfg.APIKey != "pdl_live_apikey_test" || cfg.ClientToken != "live_client_test" || cfg.WebhookSecret != "pdl_ntfset_test" {
		t.Fatalf("quoted credentials were not normalized")
	}
}
