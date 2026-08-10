package services

import "testing"

func TestProviderFromSolanaRPCURLPreservesActualProvenance(t *testing.T) {
	cases := map[string]string{
		"https://solana-mainnet.g.alchemy.com/v2/key": "alchemy",
		"https://mainnet.helius-rpc.com/?api-key=x":       "helius",
		"https://example.solana-mainnet.quiknode.pro/key": "quicknode",
		"https://rpc.triton.one":                          "triton",
		"http://127.0.0.1:8899":                           "solana_rpc",
		"https://rpc.koschei.internal":                    "solana_rpc",
		"":                                                "unconfigured",
	}
	for raw, want := range cases {
		if got := providerFromSolanaRPCURL(raw); got != want {
			t.Fatalf("providerFromSolanaRPCURL(%q)=%q want=%q", raw, got, want)
		}
	}
}

func TestResolvedArvisProviderDoesNotDefaultToAlchemy(t *testing.T) {
	t.Setenv("SOLANA_RPC_URL", "http://127.0.0.1:8899")
	if got := resolvedArvisProvider(); got != "solana_rpc" {
		t.Fatalf("resolved provider=%q", got)
	}
}
