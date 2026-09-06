package services

import (
	"net/url"
	"os"
	"strings"
)

const (
	polarProductionAPIBase = "https://api.polar.sh/v1"
	polarSandboxAPIBase    = "https://sandbox-api.polar.sh/v1"
)

type PolarConfig struct {
	AccessToken   string
	WebhookSecret string
	Environment   string
	APIBaseURL    string
	SuccessURL    string
	ReturnURL     string
	Products      map[string]string
}

func LoadPolarConfigFromEnv() PolarConfig {
	environment := strings.ToLower(strings.TrimSpace(os.Getenv("POLAR_ENVIRONMENT")))
	if environment == "" {
		environment = "production"
	}
	baseURL := polarProductionAPIBase
	if environment == "sandbox" {
		baseURL = polarSandboxAPIBase
	}
	return PolarConfig{
		AccessToken:   strings.TrimSpace(os.Getenv("POLAR_ACCESS_TOKEN")),
		WebhookSecret: strings.TrimSpace(os.Getenv("POLAR_WEBHOOK_SECRET")),
		Environment:   environment,
		APIBaseURL:    baseURL,
		SuccessURL:    trustedPolarRedirectURL(os.Getenv("POLAR_SUCCESS_URL")),
		ReturnURL:     trustedPolarRedirectURL(os.Getenv("POLAR_RETURN_URL")),
		Products: map[string]string{
			"professional":      strings.TrimSpace(os.Getenv("POLAR_PRODUCT_PROFESSIONAL_ID")),
			"legacy_starter":    strings.TrimSpace(os.Getenv("POLAR_PRODUCT_STARTER_ID")),
			"legacy_enterprise": strings.TrimSpace(os.Getenv("POLAR_PRODUCT_ENTERPRISE_ID")),
		},
	}
}

// ProductID returns only the currently sellable Professional product. Legacy
// product IDs are retained solely so existing subscription webhooks can still
// be recognized and normalized into Professional access.
func (c PolarConfig) ProductID(plan string) string {
	if c.Products == nil || strings.ToLower(strings.TrimSpace(plan)) != "professional" {
		return ""
	}
	return strings.TrimSpace(c.Products["professional"])
}

func (c PolarConfig) PlanForProduct(productID string) string {
	productID = strings.TrimSpace(productID)
	if productID == "" || c.Products == nil {
		return ""
	}
	for _, key := range []string{"professional", "legacy_starter", "legacy_enterprise"} {
		if configured := strings.TrimSpace(c.Products[key]); configured != "" && configured == productID {
			return "professional"
		}
	}
	return ""
}

func (c PolarConfig) CheckoutConfigured(plan string) bool {
	return strings.TrimSpace(c.AccessToken) != "" && c.ProductID(plan) != "" && validPolarEnvironment(c.Environment)
}

func (c PolarConfig) WebhookConfigured() bool {
	return strings.TrimSpace(c.WebhookSecret) != "" && validPolarEnvironment(c.Environment)
}

func validPolarEnvironment(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "production", "sandbox":
		return true
	default:
		return false
	}
}

func trustedPolarRedirectURL(raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.Fragment != "" {
		return ""
	}
	return u.String()
}
