package web3

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"koschei/api/internal/cache"
)

func configureWeb3SignaturePressureTest(t *testing.T, primaryURL, fallbackURL string) {
	t.Helper()
	resetSolanaRPCSignaturePressureForTest()
	t.Setenv("APP_ENV", "production")
	t.Setenv("SOLANA_RPC_SIGNATURE_GUARD_ENABLED", "true")
	t.Setenv("SOLANA_RPC_URL", primaryURL)
	t.Setenv("SOLANA_RPC_FALLBACK_URL", fallbackURL)
	t.Setenv("SOLANA_RPC_MIN_INTERVAL_MS", "0")
	t.Setenv("SOLANA_RPC_ENDPOINT_TIMEOUT_MS", "500")
	t.Setenv("SOLANA_RPC_429_COOLDOWN_SECONDS", "1")
	t.Setenv("SOLANA_RPC_TIMEOUT_COOLDOWN_SECONDS", "30")
}

func newWeb3SignatureTestRPC(client *http.Client, prefix string) *SolanaRPC {
	return &SolanaRPC{Client: client, Cache: cache.NewNoop(), KeyPrefix: prefix}
}

func callWeb3SignatureTest(ctx context.Context, rpc *SolanaRPC, address string) error {
	var out []struct {
		Signature string `json:"signature"`
	}
	return rpc.Call(ctx, "solana-mainnet", "getSignaturesForAddress", []any{address, map[string]any{"limit": 1}}, &out, time.Minute)
}

func writeWeb3SignatureResult(w http.ResponseWriter, signature string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"signature":%q,"slot":1,"err":null,"blockTime":1}]}`, signature)
}

func TestSignaturePressureCooldownIsSharedAcrossRPCInstances(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":429,"message":"capacity"}}`))
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := fallbackCalls.Add(1)
		writeWeb3SignatureResult(w, fmt.Sprintf("fallback-%d", call))
	}))
	defer fallback.Close()

	configureWeb3SignaturePressureTest(t, primary.URL, fallback.URL)
	rpcOne := newWeb3SignatureTestRPC(fallback.Client(), "one")
	rpcTwo := newWeb3SignatureTestRPC(fallback.Client(), "two")

	if err := callWeb3SignatureTest(context.Background(), rpcOne, "address-one"); err != nil {
		t.Fatalf("first signature call failed: %v", err)
	}
	if err := callWeb3SignatureTest(context.Background(), rpcTwo, "address-two"); err != nil {
		t.Fatalf("second signature call failed: %v", err)
	}
	if got := primaryCalls.Load(); got != 1 {
		t.Fatalf("primary calls=%d, want 1 across separate RPC instances", got)
	}
	if got := fallbackCalls.Load(); got != 2 {
		t.Fatalf("fallback calls=%d, want 2", got)
	}
}

func TestSignaturePressureSerializesConcurrentRPCInstances(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		time.Sleep(80 * time.Millisecond)
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":429,"message":"capacity"}}`))
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := fallbackCalls.Add(1)
		writeWeb3SignatureResult(w, fmt.Sprintf("fallback-%d", call))
	}))
	defer fallback.Close()

	configureWeb3SignaturePressureTest(t, primary.URL, fallback.URL)

	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			rpc := newWeb3SignatureTestRPC(fallback.Client(), fmt.Sprintf("rpc-%d", index))
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			errs <- callWeb3SignatureTest(ctx, rpc, fmt.Sprintf("address-%d", index))
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent signature call failed: %v", err)
		}
	}
	if got := primaryCalls.Load(); got != 1 {
		t.Fatalf("primary calls=%d, want one pressure hit", got)
	}
	if got := fallbackCalls.Load(); got != 3 {
		t.Fatalf("fallback calls=%d, want 3", got)
	}
}

func TestSignaturePressureTimeoutCooldownIsSharedAcrossRPCInstances(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		time.Sleep(200 * time.Millisecond)
		writeWeb3SignatureResult(w, "late-primary")
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := fallbackCalls.Add(1)
		writeWeb3SignatureResult(w, fmt.Sprintf("fallback-%d", call))
	}))
	defer fallback.Close()

	configureWeb3SignaturePressureTest(t, primary.URL, fallback.URL)
	t.Setenv("SOLANA_RPC_ENDPOINT_TIMEOUT_MS", "50")
	rpcOne := newWeb3SignatureTestRPC(fallback.Client(), "timeout-one")
	rpcTwo := newWeb3SignatureTestRPC(fallback.Client(), "timeout-two")

	ctxOne, cancelOne := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancelOne()
	if err := callWeb3SignatureTest(ctxOne, rpcOne, "address-one"); err != nil {
		t.Fatalf("first timeout fallback failed: %v", err)
	}
	ctxTwo, cancelTwo := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancelTwo()
	if err := callWeb3SignatureTest(ctxTwo, rpcTwo, "address-two"); err != nil {
		t.Fatalf("second timeout fallback failed: %v", err)
	}
	if got := primaryCalls.Load(); got != 1 {
		t.Fatalf("timed-out primary calls=%d, want 1 across separate RPC instances", got)
	}
	if got := fallbackCalls.Load(); got != 2 {
		t.Fatalf("fallback calls=%d, want 2", got)
	}
}

func TestSignaturePressureProduction429CooldownHasFiveMinuteFloor(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("SOLANA_RPC_429_COOLDOWN_SECONDS", "1")
	if got := solanaRPCSignature429Cooldown(""); got < 5*time.Minute {
		t.Fatalf("production signature cooldown=%s, want at least 5m", got)
	}
}
