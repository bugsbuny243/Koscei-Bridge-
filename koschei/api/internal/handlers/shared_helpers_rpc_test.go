package handlers

import "testing"

func TestSolanaRPCURLPrefersExplicitNativeEndpointOverLegacyAlchemyKey(t *testing.T) {
	t.Setenv("SOLANA_RPC_URL", "https://rpc.koschei.internal")
	t.Setenv("WEB3_PROVIDER", "auto")
	t.Setenv("SECURITY_PROVIDER", "auto")
	t.Setenv("ALCHEMY_SOLANA_RPC_URL", "")
	t.Setenv("HELIUS_SOLANA_RPC_URL", "")
	t.Setenv("QUICKNODE_SOLANA_RPC_URL", "")

	got := solanaRPCURL("solana-mainnet", "legacy-alchemy-key")
	if got != "https://rpc.koschei.internal" {
		t.Fatalf("explicit SOLANA_RPC_URL must win over legacy API key, got %q", got)
	}
}

func TestSolanaRPCURLFallsBackToPublicSolanaWithoutProviderConfig(t *testing.T) {
	t.Setenv("SOLANA_RPC_URL", "")
	t.Setenv("ALCHEMY_SOLANA_RPC_URL", "")
	t.Setenv("HELIUS_SOLANA_RPC_URL", "")
	t.Setenv("QUICKNODE_SOLANA_RPC_URL", "")
	t.Setenv("ALCHEMY_API_KEY", "")
	t.Setenv("WEB3_PROVIDER", "auto")
	t.Setenv("SECURITY_PROVIDER", "auto")

	got := solanaRPCURL("solana-mainnet", "")
	if got != "https://api.mainnet-beta.solana.com" {
		t.Fatalf("provider-free mainnet fallback=%q", got)
	}
}
