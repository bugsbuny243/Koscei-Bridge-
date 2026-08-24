package services

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func configureSolanaRPCSignatureGuardTest(t *testing.T, primaryURL, fallbackURL string) {
	t.Helper()
	resetSolanaRPCCachesForTest()
	resetSolanaRPCSignaturePressureForTest()
	t.Setenv("APP_ENV", "production")
	t.Setenv("SOLANA_RPC_SIGNATURE_GUARD_ENABLED", "true")
	t.Setenv("SOLANA_RPC_URL", primaryURL)
	t.Setenv("SOLANA_RPC_FALLBACK_URL", fallbackURL)
	t.Setenv("SOLANA_RPC_MIN_INTERVAL_MS", "0")
	t.Setenv("SOLANA_RPC_MAX_429_RETRIES", "0")
	t.Setenv("SOLANA_RPC_429_COOLDOWN_SECONDS", "30")
	t.Setenv("SOLANA_RPC_SIGNATURE_PRIMARY_TIMEOUT_MS", "500")
}

func writeSignatureResult(w http.ResponseWriter, signature string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":[{"signature":%q,"slot":1,"err":null,"blockTime":1}]}`, signature)
}

func TestServicesSignatureGuardMovesToFallbackAfter429AndKeepsPrimaryCooling(t *testing.T) {
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
		writeSignatureResult(w, fmt.Sprintf("fallback-%d", call))
	}))
	defer fallback.Close()

	configureSolanaRPCSignatureGuardTest(t, primary.URL, fallback.URL)

	first, err := SolanaGetSignaturesForAddress(context.Background(), primary.URL, "address-one", 1)
	if err != nil {
		t.Fatalf("first signature lookup failed: %v", err)
	}
	second, err := SolanaGetSignaturesForAddress(context.Background(), primary.URL, "address-two", 1)
	if err != nil {
		t.Fatalf("second signature lookup failed: %v", err)
	}
	if len(first) != 1 || len(second) != 1 {
		t.Fatalf("unexpected fallback results first=%#v second=%#v", first, second)
	}
	if got := primaryCalls.Load(); got != 1 {
		t.Fatalf("primary calls=%d, want 1 while cooldown is active", got)
	}
	if got := fallbackCalls.Load(); got != 2 {
		t.Fatalf("fallback calls=%d, want 2", got)
	}
}

func TestServicesSignatureGuardSerializesConcurrentPressure(t *testing.T) {
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
		writeSignatureResult(w, fmt.Sprintf("fallback-%d", call))
	}))
	defer fallback.Close()

	configureSolanaRPCSignatureGuardTest(t, primary.URL, fallback.URL)

	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for i := 0; i < 3; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_, err := SolanaGetSignaturesForAddress(ctx, primary.URL, fmt.Sprintf("address-%d", index), 1)
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent signature lookup failed: %v", err)
		}
	}
	if got := primaryCalls.Load(); got != 1 {
		t.Fatalf("primary calls=%d, want a single in-flight pressure hit", got)
	}
	if got := fallbackCalls.Load(); got != 3 {
		t.Fatalf("fallback calls=%d, want 3", got)
	}
}

func TestServicesSignatureGuardPreservesFallbackBudgetAfterPrimaryTimeout(t *testing.T) {
	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		time.Sleep(200 * time.Millisecond)
		writeSignatureResult(w, "late-primary")
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		writeSignatureResult(w, "fallback-ok")
	}))
	defer fallback.Close()

	configureSolanaRPCSignatureGuardTest(t, primary.URL, fallback.URL)
	t.Setenv("SOLANA_RPC_SIGNATURE_PRIMARY_TIMEOUT_MS", "50")

	ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
	defer cancel()
	started := time.Now()
	result, err := SolanaGetSignaturesForAddress(ctx, primary.URL, "address", 1)
	if err != nil {
		t.Fatalf("timeout fallback failed: %v", err)
	}
	if elapsed := time.Since(started); elapsed >= 400*time.Millisecond {
		t.Fatalf("fallback consumed too much parent deadline: %s", elapsed)
	}
	if len(result) != 1 || result[0].Signature != "fallback-ok" {
		t.Fatalf("unexpected timeout fallback result: %#v", result)
	}
	if primaryCalls.Load() != 1 || fallbackCalls.Load() != 1 {
		t.Fatalf("unexpected calls primary=%d fallback=%d", primaryCalls.Load(), fallbackCalls.Load())
	}
}
