package services

import "testing"

func TestHeliusEnhancedHistoryIsDisabledByDefault(t *testing.T) {
	t.Setenv("KOSCHEI_HELIUS_ENHANCED_HISTORY_ENABLED", "")
	t.Setenv("HELIUS_API_KEY", "configured-key")

	if got := heliusEnhancedHistoryAPIKey("https://mainnet.helius-rpc.com/?api-key=url-key"); got != "" {
		t.Fatalf("enhanced holder history must stay disabled without explicit opt-in, got key %q", got)
	}
	if got := heliusEnhancedAPIKey("https://mainnet.helius-rpc.com/?api-key=url-key"); got != "configured-key" {
		t.Fatalf("shared Helius provider key must remain available for DAS/standard enrichment, got %q", got)
	}
}

func TestHeliusEnhancedHistoryRequiresExplicitOptIn(t *testing.T) {
	t.Setenv("KOSCHEI_HELIUS_ENHANCED_HISTORY_ENABLED", "true")
	t.Setenv("HELIUS_API_KEY", "configured-key")

	if got := heliusEnhancedHistoryAPIKey("https://mainnet.helius-rpc.com/?api-key=url-key"); got != "configured-key" {
		t.Fatalf("expected explicit HELIUS_API_KEY after enhanced-history opt-in, got %q", got)
	}
}

func TestHeliusProviderKeyCanResolveFromHeliusRPCURL(t *testing.T) {
	t.Setenv("KOSCHEI_HELIUS_ENHANCED_HISTORY_ENABLED", "1")
	t.Setenv("HELIUS_API_KEY", "")

	if got := heliusEnhancedHistoryAPIKey("https://mainnet.helius-rpc.com/?api-key=url-key"); got != "url-key" {
		t.Fatalf("expected api-key from Helius RPC URL after enhanced-history opt-in, got %q", got)
	}
	if got := heliusEnhancedAPIKey("https://mainnet.helius-rpc.com/?api-key=url-key"); got != "url-key" {
		t.Fatalf("expected shared provider key from Helius RPC URL, got %q", got)
	}
	if got := heliusEnhancedAPIKey("https://example.invalid/?api-key=wrong-provider"); got != "" {
		t.Fatalf("non-Helius RPC URL must not expose its query value as a Helius key, got %q", got)
	}
}

func TestHeliusEnhancedHistoryOptInParserIsExplicit(t *testing.T) {
	for _, value := range []string{"true", "TRUE", "1", "yes", "on"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("KOSCHEI_HELIUS_ENHANCED_HISTORY_ENABLED", value)
			if !heliusEnhancedHistoryEnabled() {
				t.Fatalf("expected %q to enable enhanced history", value)
			}
		})
	}
	for _, value := range []string{"", "false", "0", "no", "off", "unexpected"} {
		t.Run("disabled_"+value, func(t *testing.T) {
			t.Setenv("KOSCHEI_HELIUS_ENHANCED_HISTORY_ENABLED", value)
			if heliusEnhancedHistoryEnabled() {
				t.Fatalf("expected %q to keep enhanced history disabled", value)
			}
		})
	}
}
