package services

import (
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"koschei/api/internal/web3"
)

type governorRoundTripper func(*http.Request) (*http.Response, error)

func (f governorRoundTripper) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

func TestServiceFailoverPublishes429ToSharedProviderGovernor(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("SOLANA_RPC_GOVERNOR_ENABLED", "true")
	t.Setenv("SOLANA_RPC_MIN_INTERVAL_MS", "0")
	t.Setenv("SOLANA_RPC_FAILOVER_ENABLED", "true")
	t.Setenv("SOLANA_RPC_URL", "https://primary.example/rpc")
	t.Setenv("SOLANA_RPC_FALLBACK_URL", "https://backup.example/rpc")
	web3.ResetSolanaRPCProviderGovernorForTest()
	defer web3.ResetSolanaRPCProviderGovernorForTest()

	transport := &solanaFailoverTransport{base: governorRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "primary.example" {
			return &http.Response{
				StatusCode: http.StatusTooManyRequests,
				Header:     http.Header{"Retry-After": []string{"1"}},
				Body:       io.NopCloser(strings.NewReader(`{"error":"rate limited"}`)),
				Request:    r,
			}, nil
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","result":{}}`)),
			Request:    r,
		}, nil
	})}

	req, err := http.NewRequest(http.MethodPost, "https://primary.example/rpc", strings.NewReader(`{"jsonrpc":"2.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Koschei-RPC-Method", "getTransaction")
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request == nil || resp.Request.URL.Hostname() != "backup.example" {
		t.Fatalf("fallback response was not returned: status=%d request=%v", resp.StatusCode, resp.Request)
	}
	if _, cooling := web3.SolanaRPCProviderCooldown("https://primary.example/another-api-key"); !cooling {
		t.Fatal("service-layer 429 was not published to shared governor")
	}
	if _, cooling := web3.SolanaRPCProviderCooldown("https://backup.example/rpc"); cooling {
		t.Fatal("primary cooldown leaked to backup provider")
	}
}

func TestServiceFailoverSkipsPrimaryAlreadyCoolingInSharedGovernor(t *testing.T) {
	t.Setenv("APP_ENV", "test")
	t.Setenv("SOLANA_RPC_GOVERNOR_ENABLED", "true")
	t.Setenv("SOLANA_RPC_MIN_INTERVAL_MS", "0")
	t.Setenv("SOLANA_RPC_FAILOVER_ENABLED", "true")
	t.Setenv("SOLANA_RPC_URL", "https://primary.example/rpc")
	t.Setenv("SOLANA_RPC_FALLBACK_URL", "https://backup.example/rpc")
	web3.ResetSolanaRPCProviderGovernorForTest()
	defer web3.ResetSolanaRPCProviderGovernorForTest()
	web3.DeferSolanaRPCProvider("https://primary.example/rpc", time.Minute)

	var primaryCalls atomic.Int32
	var backupCalls atomic.Int32
	transport := &solanaFailoverTransport{base: governorRoundTripper(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "primary.example" {
			primaryCalls.Add(1)
		} else if r.URL.Hostname() == "backup.example" {
			backupCalls.Add(1)
		}
		return &http.Response{
			StatusCode: http.StatusOK,
			Header:     make(http.Header),
			Body:       io.NopCloser(strings.NewReader(`{"jsonrpc":"2.0","result":{}}`)),
			Request:    r,
		}, nil
	})}

	req, err := http.NewRequest(http.MethodPost, "https://primary.example/rpc", strings.NewReader(`{"jsonrpc":"2.0"}`))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("X-Koschei-RPC-Method", "getTransactionBatch")
	resp, err := transport.RoundTrip(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if primaryCalls.Load() != 0 {
		t.Fatalf("cooling primary was still hit %d times", primaryCalls.Load())
	}
	if backupCalls.Load() != 1 {
		t.Fatalf("backup calls=%d want 1", backupCalls.Load())
	}
}
