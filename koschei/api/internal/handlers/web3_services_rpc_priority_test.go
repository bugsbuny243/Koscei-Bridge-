package handlers

import "testing"

func TestConfiguredRPCProvidersPrefersCanonicalSolanaRPC(t *testing.T) {
	t.Setenv("SOLANA_RPC_URL", "https://rpc.koschei.internal")
	t.Setenv("ALCHEMY_SOLANA_RPC_URL", "https://alchemy.example")
	t.Setenv("HELIUS_SOLANA_RPC_URL", "https://helius.example")
	t.Setenv("QUICKNODE_SOLANA_RPC_URL", "https://quicknode.example")
	t.Setenv("ALCHEMY_API_KEY", "legacy-key")

	providers := configuredRPCProviders()
	if len(providers) != 4 {
		t.Fatalf("provider count=%d, want 4: %#v", len(providers), providers)
	}
	if providers[0].Name != "solana_rpc" || providers[0].URL != "https://rpc.koschei.internal" || providers[0].Priority != 1 {
		t.Fatalf("canonical Solana RPC must be first: %#v", providers[0])
	}
	if providers[1].Name != "alchemy" || providers[1].URL != "https://alchemy.example" {
		t.Fatalf("unexpected Alchemy fallback: %#v", providers[1])
	}
}

func TestConfiguredRPCProvidersSupportsLegacyProviderURLAliases(t *testing.T) {
	t.Setenv("SOLANA_RPC_URL", "")
	t.Setenv("ALCHEMY_SOLANA_RPC_URL", "")
	t.Setenv("HELIUS_SOLANA_RPC_URL", "")
	t.Setenv("QUICKNODE_SOLANA_RPC_URL", "")
	t.Setenv("SOLANA_ALCHEMY_RPC_URL", "https://legacy-alchemy.example")
	t.Setenv("SOLANA_HELIUS_RPC_URL", "https://legacy-helius.example")
	t.Setenv("SOLANA_QUICKNODE_RPC_URL", "https://legacy-quicknode.example")
	t.Setenv("ALCHEMY_API_KEY", "")

	providers := configuredRPCProviders()
	if len(providers) != 3 {
		t.Fatalf("provider count=%d, want 3: %#v", len(providers), providers)
	}
	if providers[0].URL != "https://legacy-alchemy.example" || providers[1].URL != "https://legacy-helius.example" || providers[2].URL != "https://legacy-quicknode.example" {
		t.Fatalf("legacy aliases were not preserved: %#v", providers)
	}
}

func TestConfiguredRPCProvidersDoesNotDuplicateCanonicalEndpointAsAlchemy(t *testing.T) {
	t.Setenv("SOLANA_RPC_URL", "https://rpc.koschei.internal")
	t.Setenv("ALCHEMY_SOLANA_RPC_URL", "")
	t.Setenv("SOLANA_ALCHEMY_RPC_URL", "")
	t.Setenv("HELIUS_SOLANA_RPC_URL", "")
	t.Setenv("SOLANA_HELIUS_RPC_URL", "")
	t.Setenv("QUICKNODE_SOLANA_RPC_URL", "")
	t.Setenv("SOLANA_QUICKNODE_RPC_URL", "")
	t.Setenv("ALCHEMY_API_KEY", "legacy-key")

	providers := configuredRPCProviders()
	if len(providers) != 2 {
		t.Fatalf("provider count=%d, want canonical + Alchemy fallback: %#v", len(providers), providers)
	}
	if providers[0].Name != "solana_rpc" || providers[1].Name != "alchemy" {
		t.Fatalf("unexpected provider order: %#v", providers)
	}
	if providers[0].URL == providers[1].URL {
		t.Fatalf("canonical endpoint was duplicated under provider provenance: %#v", providers)
	}
}
