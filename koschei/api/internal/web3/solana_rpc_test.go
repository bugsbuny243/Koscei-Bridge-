package web3

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"koschei/api/internal/cache"
)

func TestCacheKeyIncludesMethod(t *testing.T) {
	rpc := &SolanaRPC{Cache: cache.NewMemory(), KeyPrefix: "test"}
	a := rpc.CacheKey("solana-mainnet", "getTransaction", []any{"sig"})
	b := rpc.CacheKey("solana-mainnet", "getTokenSupply", []any{"sig"})
	if a == b {
		t.Fatalf("cache keys should differ by method")
	}
}

func TestTTLForKnownMethods(t *testing.T) {
	if TTLFor("getTransaction", nil) != 24*time.Hour {
		t.Fatalf("unexpected tx ttl")
	}
	if TTLFor("getTokenSupply", nil) != time.Minute {
		t.Fatalf("unexpected supply ttl")
	}
	if TTLFor("getTokenLargestAccounts", nil) != 5*time.Minute {
		t.Fatalf("unexpected holders ttl")
	}
}

func TestSolanaRPCUsesConfiguredURL(t *testing.T) {
	t.Setenv("SOLANA_RPC_URL", "https://rpc.example.test")
	got := SolanaRPCURL("solana-mainnet", "alchemy-key")
	if got != "https://rpc.example.test" {
		t.Fatalf("configured rpc URL should win, got %q", got)
	}
}

func TestSolanaRPCFallsBackAfterProviderRateLimit(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls.Add(1)
		http.Error(w, "capacity exceeded", http.StatusTooManyRequests)
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"value":"ok"}}`)
	}))
	defer fallback.Close()

	t.Setenv("SOLANA_RPC_URL", primary.URL)
	t.Setenv("SOLANA_RPC_FALLBACK_URL", fallback.URL)
	rpc := &SolanaRPC{Client: fallback.Client(), Cache: cache.NewNoop(), KeyPrefix: "test"}
	var out struct {
		Value string `json:"value"`
	}
	if err := rpc.Call(context.Background(), "solana-mainnet", "getVersion", []any{}, &out, time.Second); err != nil {
		t.Fatalf("expected fallback success, got %v", err)
	}
	if out.Value != "ok" {
		t.Fatalf("unexpected fallback result %q", out.Value)
	}
	if primaryCalls.Load() != 1 || fallbackCalls.Load() != 1 {
		t.Fatalf("expected one call per endpoint, primary=%d fallback=%d", primaryCalls.Load(), fallbackCalls.Load())
	}
}

func TestSolanaRPCFallsBackAfterEndpointTimeout(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		primaryCalls.Add(1)
		time.Sleep(200 * time.Millisecond)
		http.Error(w, "late primary", http.StatusGatewayTimeout)
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fallbackCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprint(w, `{"jsonrpc":"2.0","id":1,"result":{"value":"fallback-ok"}}`)
	}))
	defer fallback.Close()

	t.Setenv("SOLANA_RPC_URL", primary.URL)
	t.Setenv("SOLANA_RPC_FALLBACK_URL", fallback.URL)
	t.Setenv("SOLANA_RPC_ENDPOINT_TIMEOUT_MS", "75")
	rpc := &SolanaRPC{Client: fallback.Client(), Cache: cache.NewNoop(), KeyPrefix: "test"}
	var out struct {
		Value string `json:"value"`
	}
	started := time.Now()
	if err := rpc.Call(context.Background(), "solana-mainnet", "getVersion", []any{}, &out, time.Second); err != nil {
		t.Fatalf("expected timeout fallback success, got %v", err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("fallback took too long: %s", elapsed)
	}
	if out.Value != "fallback-ok" || primaryCalls.Load() != 1 || fallbackCalls.Load() != 1 {
		t.Fatalf("unexpected fallback result=%q primary=%d fallback=%d", out.Value, primaryCalls.Load(), fallbackCalls.Load())
	}
}

func TestUniqueRPCURLsRemovesDuplicates(t *testing.T) {
	got := uniqueRPCURLs("https://rpc.test", " https://rpc.test ", "", "https://fallback.test")
	if len(got) != 2 {
		t.Fatalf("expected two unique endpoints, got %v", got)
	}
}

func TestSolanaRPCFallbackPrefersDifferentConfiguredProvider(t *testing.T) {
	t.Setenv("SOLANA_RPC_URL", "https://mainnet.helius-rpc.com/?api-key=primary-secret")
	t.Setenv("SOLANA_RPC_FALLBACK_URL", "")
	t.Setenv("ALCHEMY_SOLANA_RPC_URL", "https://solana-mainnet.g.alchemy.com/v2/fallback-secret")
	t.Setenv("HELIUS_SOLANA_RPC_URL", "")
	t.Setenv("QUICKNODE_SOLANA_RPC_URL", "")
	t.Setenv("ALCHEMY_API_KEY", "")
	got := SolanaRPCFallbackURL("solana-mainnet")
	if RPCProviderHost(got) != "solana-mainnet.g.alchemy.com" {
		t.Fatalf("fallback host=%q url=%q", RPCProviderHost(got), got)
	}
}

func TestSolanaRPCBlankNetworkUsesSOLANANetworkAndProviderPreference(t *testing.T) {
	t.Setenv("SOLANA_NETWORK", "mainnet")
	t.Setenv("SOLANA_RPC_URL", "")
	t.Setenv("WEB3_PROVIDER", "helius")
	t.Setenv("KOSCHEI_SECURITY_PROVIDER", "auto")
	t.Setenv("HELIUS_SOLANA_RPC_URL", "https://helius.example.test")
	t.Setenv("ALCHEMY_SOLANA_RPC_URL", "https://alchemy.example.test")
	t.Setenv("QUICKNODE_SOLANA_RPC_URL", "https://quicknode.example.test")
	if got := SolanaRPCURL("", ""); got != "https://helius.example.test" {
		t.Fatalf("blank network/provider preference got %q", got)
	}
}

func TestSecurityProviderDrivesRPCWhenWeb3ProviderAuto(t *testing.T) {
	t.Setenv("SOLANA_NETWORK", "mainnet")
	t.Setenv("SOLANA_RPC_URL", "")
	t.Setenv("WEB3_PROVIDER", "auto")
	t.Setenv("KOSCHEI_SECURITY_PROVIDER", "quicknode")
	t.Setenv("QUICKNODE_SOLANA_RPC_URL", "https://quicknode.example.test")
	t.Setenv("ALCHEMY_SOLANA_RPC_URL", "https://alchemy.example.test")
	if got := SolanaRPCURL("", ""); got != "https://quicknode.example.test" {
		t.Fatalf("security provider preference got %q", got)
	}
}
