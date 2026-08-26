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

	"koschei/api/internal/web3"
)

func configureSolanaTransactionSingleflightTest(t *testing.T) {
	t.Helper()
	resetSolanaRPCCachesForTest()
	web3.ResetSolanaRPCProviderGovernorForTest()
	t.Setenv("APP_ENV", "test")
	t.Setenv("SOLANA_RPC_GOVERNOR_ENABLED", "false")
	t.Setenv("SOLANA_RPC_FAILOVER_ENABLED", "false")
	t.Setenv("SOLANA_RPC_MIN_INTERVAL_MS", "0")
	t.Setenv("SOLANA_RPC_MAX_429_RETRIES", "0")
}

func writeTransactionResult(w http.ResponseWriter, signature string) {
	w.Header().Set("Content-Type", "application/json")
	_, _ = fmt.Fprintf(w, `{"jsonrpc":"2.0","id":1,"result":{"slot":1,"signature":%q}}`, signature)
}

func TestSolanaTransactionSingleflightCollapsesConcurrentIdenticalFetches(t *testing.T) {
	configureSolanaTransactionSingleflightTest(t)

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(100 * time.Millisecond)
		writeTransactionResult(w, "same-signature")
	}))
	defer server.Close()

	const callers = 8
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := SolanaGetTransactionJSONParsed(context.Background(), server.URL, "same-signature")
			if err == nil && result["signature"] != "same-signature" {
				err = fmt.Errorf("unexpected transaction result: %#v", result)
			}
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream getTransaction calls=%d want 1", got)
	}
}

func TestSolanaTransactionSingleflightKeepsDifferentSignaturesIndependent(t *testing.T) {
	configureSolanaTransactionSingleflightTest(t)

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(40 * time.Millisecond)
		writeTransactionResult(w, "ok")
	}))
	defer server.Close()

	var wg sync.WaitGroup
	for _, signature := range []string{"signature-a", "signature-b"} {
		signature := signature
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := SolanaGetTransactionJSONParsed(context.Background(), server.URL, signature); err != nil {
				t.Errorf("signature %s failed: %v", signature, err)
			}
		}()
	}
	wg.Wait()
	if got := calls.Load(); got != 2 {
		t.Fatalf("upstream getTransaction calls=%d want 2 for distinct signatures", got)
	}
}

func TestSolanaTransactionSingleflightDoesNotCacheCompletedResponses(t *testing.T) {
	configureSolanaTransactionSingleflightTest(t)

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		call := calls.Add(1)
		writeTransactionResult(w, fmt.Sprintf("call-%d", call))
	}))
	defer server.Close()

	first, err := SolanaGetTransactionJSONParsed(context.Background(), server.URL, "same-signature")
	if err != nil {
		t.Fatal(err)
	}
	second, err := SolanaGetTransactionJSONParsed(context.Background(), server.URL, "same-signature")
	if err != nil {
		t.Fatal(err)
	}
	if first["signature"] == second["signature"] {
		t.Fatalf("completed transaction response was unexpectedly cached: first=%#v second=%#v", first, second)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("upstream getTransaction calls=%d want 2 after first call completed", got)
	}
}

func TestSolanaTransactionSingleflightCollapsesConcurrentFailover(t *testing.T) {
	configureSolanaTransactionSingleflightTest(t)
	t.Setenv("SOLANA_RPC_FAILOVER_ENABLED", "true")

	var primaryCalls atomic.Int32
	primary := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		primaryCalls.Add(1)
		time.Sleep(80 * time.Millisecond)
		w.Header().Set("Retry-After", "1")
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"error":{"code":429,"message":"capacity"}}`))
	}))
	defer primary.Close()

	var fallbackCalls atomic.Int32
	fallback := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		fallbackCalls.Add(1)
		writeTransactionResult(w, "fallback-ok")
	}))
	defer fallback.Close()
	t.Setenv("SOLANA_RPC_FALLBACK_URL", fallback.URL)

	const callers = 6
	start := make(chan struct{})
	errs := make(chan error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			result, err := SolanaGetTransactionJSONParsed(context.Background(), primary.URL, "same-signature")
			if err == nil && result["signature"] != "fallback-ok" {
				err = fmt.Errorf("unexpected fallback result: %#v", result)
			}
			errs <- err
		}()
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if got := primaryCalls.Load(); got != 1 {
		t.Fatalf("primary getTransaction calls=%d want 1", got)
	}
	if got := fallbackCalls.Load(); got != 1 {
		t.Fatalf("fallback getTransaction calls=%d want 1", got)
	}
}
