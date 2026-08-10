package services

import "testing"

func TestSecurityRadarDefaultSourceIsProviderNeutral(t *testing.T) {
	if securityRadarDefaultSource != "solana_rpc" {
		t.Fatalf("default source must remain provider-neutral, got %q", securityRadarDefaultSource)
	}
	if got := firstSecurityRadarString("", securityRadarDefaultSource); got != "solana_rpc" {
		t.Fatalf("blank source must resolve to solana_rpc, got %q", got)
	}
	if got := firstSecurityRadarString("helius_polling", securityRadarDefaultSource); got != "helius_polling" {
		t.Fatalf("explicit provider provenance must be preserved, got %q", got)
	}
}
