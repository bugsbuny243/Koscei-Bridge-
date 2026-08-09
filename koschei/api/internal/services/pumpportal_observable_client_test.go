package services

import "testing"

func TestClassifyPumpPortalProviderNoticeRejectsTradeEntitlementFailure(t *testing.T) {
	payload := []byte(`{"message":"API key required to subscribe to token trades"}`)
	class, ok := classifyPumpPortalProviderNotice(payload)
	if !ok || class != "trade_subscription_rejected" {
		t.Fatalf("expected trade_subscription_rejected, got class=%q ok=%t", class, ok)
	}
}

func TestClassifyPumpPortalProviderNoticeDoesNotConsumeEvents(t *testing.T) {
	payload := []byte(`{"mint":"Mint111111111111111111111111111111111111","txType":"buy"}`)
	if class, ok := classifyPumpPortalProviderNotice(payload); ok || class != "" {
		t.Fatalf("event payload must not be classified as provider notice: class=%q ok=%t", class, ok)
	}
}

func TestClassifyPumpPortalProviderNoticeGeneric(t *testing.T) {
	payload := []byte(`{"message":"subscription successful"}`)
	class, ok := classifyPumpPortalProviderNotice(payload)
	if !ok || class != "provider_notice" {
		t.Fatalf("expected provider_notice, got class=%q ok=%t", class, ok)
	}
}
