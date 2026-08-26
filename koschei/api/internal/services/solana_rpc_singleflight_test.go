package services

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func configureSolanaTransactionSingleflightTest(t *testing.T) {
	t.Helper()
	resetSolanaRPCCachesForTest()
	t.Setenv("APP_ENV", "test")
	t.Setenv("SOLANA_RPC_GOVERNOR_ENABLED", "false")
	t.Setenv("SOLANA_RPC_FAILOVER_ENABLED", "false")
	t.Setenv("SOLANA_RPC_MIN_INTERVAL_MS", "0")
}

func TestSolanaGetTransactionJSONParsedSingleflightsConcurrentSignature(t *testing.T) {
	configureSolanaTransactionSingleflightTest(t)

	var upstreamCalls atomic.Int32
	serverEntered := make(chan struct{}, 1)
	releaseServer := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		select {
		case serverEntered <- struct{}{}:
		default:
		}
		<-releaseServer
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"slot":42,"meta":{"marker":"original"}}}`))
	}))
	defer server.Close()

	const callers = 8
	start := make(chan struct{})
	results := make([]SolanaTransactionResult, callers)
	errs := make([]error, callers)
	var wg sync.WaitGroup
	for i := 0; i < callers; i++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			<-start
			results[index], errs[index] = SolanaGetTransactionJSONParsed(context.Background(), server.URL, "same-signature")
		}(i)
	}
	close(start)
	<-serverEntered
	time.Sleep(20 * time.Millisecond)
	close(releaseServer)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Fatalf("caller %d error: %v", i, err)
		}
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("upstream getTransaction calls=%d want 1", got)
	}
	if len(results) < 2 || results[0] == nil || results[1] == nil {
		t.Fatalf("missing caller results: %#v", results)
	}
	meta0, ok := results[0]["meta"].(map[string]any)
	if !ok {
		t.Fatalf("caller 0 meta=%#v", results[0]["meta"])
	}
	meta1, ok := results[1]["meta"].(map[string]any)
	if !ok {
		t.Fatalf("caller 1 meta=%#v", results[1]["meta"])
	}
	meta0["marker"] = "mutated"
	if meta1["marker"] != "original" {
		t.Fatalf("shared mutable transaction map leaked across callers: %#v", meta1)
	}
}

func TestSolanaGetTransactionJSONParsedKeepsDistinctSignaturesIndependent(t *testing.T) {
	configureSolanaTransactionSingleflightTest(t)

	var upstreamCalls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"slot":7}}`))
	}))
	defer server.Close()

	var wg sync.WaitGroup
	for _, signature := range []string{"signature-a", "signature-b"} {
		signature := signature
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := SolanaGetTransactionJSONParsed(context.Background(), server.URL, signature); err != nil {
				t.Errorf("%s: %v", signature, err)
			}
		}()
	}
	wg.Wait()
	if got := upstreamCalls.Load(); got != 2 {
		t.Fatalf("upstream calls=%d want 2 for distinct signatures", got)
	}
}

func TestSolanaGetTransactionJSONParsedDuplicateWaiterHonorsContext(t *testing.T) {
	configureSolanaTransactionSingleflightTest(t)

	var upstreamCalls atomic.Int32
	serverEntered := make(chan struct{})
	releaseServer := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		upstreamCalls.Add(1)
		close(serverEntered)
		<-releaseServer
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"jsonrpc":"2.0","id":1,"result":{"slot":99}}`))
	}))
	defer server.Close()

	leaderDone := make(chan error, 1)
	go func() {
		_, err := SolanaGetTransactionJSONParsed(context.Background(), server.URL, "same-signature")
		leaderDone <- err
	}()
	<-serverEntered

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	_, err := SolanaGetTransactionJSONParsed(ctx, server.URL, "same-signature")
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("duplicate waiter err=%v want deadline exceeded", err)
	}
	if got := upstreamCalls.Load(); got != 1 {
		t.Fatalf("duplicate waiter created %d upstream calls, want 1", got)
	}

	close(releaseServer)
	if err := <-leaderDone; err != nil {
		t.Fatalf("leader failed after duplicate waiter cancellation: %v", err)
	}
}
