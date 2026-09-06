package handlers

import "testing"

func TestClassifyCorrelationRPCSourceRecognizesOfficialHeliusHosts(t *testing.T) {
	for _, endpoint := range []string{
		"https://mainnet.helius-rpc.com/?api-key=redacted",
		"https://devnet.helius-rpc.com/?api-key=redacted",
		"https://custom.helius-rpc.com/path?api-key=redacted",
	} {
		if got := classifyCorrelationRPCSource(endpoint); got != "helius_rpc" {
			t.Fatalf("classifyCorrelationRPCSource(%q) = %q, want helius_rpc", endpoint, got)
		}
	}
}

func TestClassifyCorrelationRPCSourceDoesNotMislabelLookalikeOrGenericRPC(t *testing.T) {
	for _, endpoint := range []string{
		"https://mainnet.helius-rpc.com.evil.example/?api-key=redacted",
		"https://api.mainnet-beta.solana.com",
		"https://example.invalid/rpc",
		"not a url",
	} {
		if got := classifyCorrelationRPCSource(endpoint); got != "canonical_solana_rpc_fallback" {
			t.Fatalf("classifyCorrelationRPCSource(%q) = %q, want canonical_solana_rpc_fallback", endpoint, got)
		}
	}
}
