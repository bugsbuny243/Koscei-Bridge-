package web3

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"koschei/api/internal/cache"
)

func TestSolanaRPCProviderGovernorSharesCooldownByHost(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("SOLANA_RPC_GOVERNOR_ENABLED", "true")
	t.Setenv("SOLANA_RPC_MIN_INTERVAL_MS", "0")
	ResetSolanaRPCProviderGovernorForTest()
	defer ResetSolanaRPCProviderGovernorForTest()

	DeferSolanaRPCProvider("https://mainnet.helius-rpc.com/key-a", time.Minute)
	if _, cooling := SolanaRPCProviderCooldown("https://mainnet.helius-rpc.com/key-b"); !cooling {
		t.Fatal("same provider host did not share cooldown across API-key paths")
	}
	if _, cooling := SolanaRPCProviderCooldown("https://solana-mainnet.g.alchemy.com/v2/key"); cooling {
		t.Fatal("cooldown leaked across provider hosts")
	}
}

func TestSolanaRPCProviderGovernorKeepsLoopbackPortsIndependent(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("SOLANA_RPC_GOVERNOR_ENABLED", "true")
	ResetSolanaRPCProviderGovernorForTest()
	defer ResetSolanaRPCProviderGovernorForTest()

	DeferSolanaRPCProvider("http://127.0.0.1:18001/rpc", time.Minute)
	if _, cooling := SolanaRPCProviderCooldown("http://127.0.0.1:18001/other-path"); !cooling {
		t.Fatal("same loopback endpoint did not share cooldown across paths")
	}
	if _, cooling := SolanaRPCProviderCooldown("http://127.0.0.1:18002/rpc"); cooling {
		t.Fatal("cooldown leaked across independent loopback ports")
	}
}

func TestSolanaRPCProviderGovernorPacesIndependentCallers(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("SOLANA_RPC_GOVERNOR_ENABLED", "true")
	t.Setenv("SOLANA_RPC_MIN_INTERVAL_MS", "35")
	ResetSolanaRPCProviderGovernorForTest()
	defer ResetSolanaRPCProviderGovernorForTest()

	endpoint := "https://mainnet.helius-rpc.com/key"
	if err := WaitForSolanaRPCProviderSlot(context.Background(), endpoint); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := WaitForSolanaRPCProviderSlot(context.Background(), endpoint); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(started); elapsed < 25*time.Millisecond {
		t.Fatalf("shared provider pacing was not enforced: elapsed=%s", elapsed)
	}
}

func TestRPCManagerPublishes429AndUsesIndependentFallback(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("SOLANA_RPC_GOVERNOR_ENABLED", "true")
	t.Setenv("SOLANA_RPC_MIN_INTERVAL_MS", "0")
	t.Setenv("SOLANA_RPC_429_COOLDOWN_SECONDS", "1")
	ResetSolanaRPCProviderGovernorForTest()
	defer ResetSolanaRPCProviderGovernorForTest()

	client := roundTrip(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "primary.example" {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     http.Header{"Retry-After": {"1"}},
				Body:       ioNopCloser{strings.NewReader(`{"jsonrpc":"2.0","error":{"code":429,"message":"rate limited"}}`)},
				Request:    r,
			}, nil
		}
		resp := jsonResponse(`{"jsonrpc":"2.0","result":{"ok":true}}`)
		resp.Request = r
		return resp, nil
	})
	manager := NewRPCManager(client, []RPCProviderConfig{
		{Name: "primary", URL: "https://primary.example/rpc", Priority: 1, MaxFailures: 5},
		{Name: "backup", URL: "https://backup.example/rpc", Priority: 2, MaxFailures: 5},
	})
	var out map[string]any
	provider, err := manager.Call(context.Background(), "getTransaction", []any{"sig"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if provider != "backup" {
		t.Fatalf("provider=%s want backup", provider)
	}
	if _, cooling := SolanaRPCProviderCooldown("https://primary.example/another-key"); !cooling {
		t.Fatal("RPCManager 429 was not published to the shared provider governor")
	}
	if _, cooling := SolanaRPCProviderCooldown("https://backup.example/rpc"); cooling {
		t.Fatal("primary cooldown poisoned fallback host")
	}
}

func TestSolanaRPCUsesFallbackWhenSharedGovernorMarksPrimaryCooling(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("SOLANA_RPC_GOVERNOR_ENABLED", "true")
	t.Setenv("SOLANA_RPC_MIN_INTERVAL_MS", "0")
	ResetSolanaRPCProviderGovernorForTest()
	defer ResetSolanaRPCProviderGovernorForTest()

	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"source":"primary"}}`))
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","result":{"source":"fallback"}}`))
	}))
	defer fallback.Close()
	fallbackURL := strings.Replace(fallback.URL, "127.0.0.1", "localhost", 1)

	t.Setenv("SOLANA_RPC_URL", primary.URL)
	t.Setenv("SOLANA_RPC_FALLBACK_URL", fallbackURL)
	DeferSolanaRPCProvider(primary.URL, time.Minute)

	rpc := NewSolanaRPC(cache.NewNoop())
	var out map[string]any
	if err := rpc.Call(context.Background(), "solana-mainnet", "getAccountInfo", []any{"target"}, &out, time.Second); err != nil {
		t.Fatal(err)
	}
	if primaryCalls.Load() != 0 {
		t.Fatalf("cooling primary was still called %d times", primaryCalls.Load())
	}
	if fallbackCalls.Load() != 1 {
		t.Fatalf("fallback calls=%d want 1", fallbackCalls.Load())
	}
	if out["source"] != "fallback" {
		t.Fatalf("unexpected fallback result: %#v", out)
	}
}
