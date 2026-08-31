package handlers

import "testing"

func TestNormalizePaymentProviderAcceptsSupportedProviders(t *testing.T) {
	tests := map[string]string{
		"shopier":        "shopier",
		" SHOPIER ":      "shopier",
		"shopier_manual": "shopier_manual",
		"owner_manual":   "owner_manual",
	}
	for input, want := range tests {
		if got := normalizePaymentProvider(input); got != want {
			t.Fatalf("normalizePaymentProvider(%q) = %q, want %q", input, got, want)
		}
	}
}

func TestNormalizePaymentProviderRejectsRetiredAndUnknownProviders(t *testing.T) {
	for _, input := range []string{"paddle", "PADDLE", "stripe", "", "unknown"} {
		if got := normalizePaymentProvider(input); got != "" {
			t.Fatalf("normalizePaymentProvider(%q) = %q, want empty fail-closed result", input, got)
		}
	}
}
