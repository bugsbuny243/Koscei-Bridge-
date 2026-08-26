package services

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
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
	// Keep a production-like local pacing interval deliberately longer than the
	// upstream request. If dedupe happened inside the transport, callers would
	// be serialized before joining and would each reach the provider.
	t.Setenv("SOLANA_RPC_MIN_INTERVAL_MS", "250")

	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		time.Sleep(75 * time.Millisecond)
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
	fallbackURL := strings.Replace(fallback.URL, "127.0.0.1", "localhost", 1)
	t.Setenv("SOLANA_RPC_FALLBACK_URL", fallbackURL)

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

func TestSolanaTransactionSingleflightLeaderCancellationDoesNotCancelSharedRPC(t *testing.T) {
	configureSolanaTransactionSingleflightTest(t)

	var calls atomic.Int32
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	requestCanceled := make(chan struct{}, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		close(requestStarted)
		select {
		case <-releaseRequest:
			writeTransactionResult(w, "shared-ok")
		case <-r.Context().Done():
			requestCanceled <- struct{}{}
		}
	}))
	defer server.Close()

	leaderCtx, cancelLeader := context.WithCancel(context.Background())
	leaderDone := make(chan error, 1)
	go func() {
		_, err := SolanaGetTransactionJSONParsed(leaderCtx, server.URL, "same-signature")
		leaderDone <- err
	}()

	<-requestStarted
	cancelLeader()
	select {
	case err := <-leaderDone:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("leader error=%v want context canceled", err)
		}
	case <-time.After(time.Second):
		t.Fatal("leader did not stop waiting after cancellation")
	}

	select {
	case <-requestCanceled:
		t.Fatal("leader cancellation propagated into shared HTTP request")
	case <-time.After(25 * time.Millisecond):
	}

	type followerResult struct {
		result SolanaTransactionResult
		err    error
	}
	followerDone := make(chan followerResult, 1)
	go func() {
		result, err := SolanaGetTransactionJSONParsed(context.Background(), server.URL, "same-signature")
		followerDone <- followerResult{result: result, err: err}
	}()

	select {
	case result := <-followerDone:
		t.Fatalf("follower returned before shared request release: result=%#v err=%v", result.result, result.err)
	case <-time.After(25 * time.Millisecond):
	}

	close(releaseRequest)
	select {
	case result := <-followerDone:
		if result.err != nil {
			t.Fatal(result.err)
		}
		if result.result["signature"] != "shared-ok" {
			t.Fatalf("follower result=%#v want shared-ok", result.result)
		}
	case <-time.After(time.Second):
		t.Fatal("follower did not receive shared transaction result")
	}
	if got := calls.Load(); got != 1 {
		t.Fatalf("upstream getTransaction calls=%d want 1 after leader cancellation", got)
	}
}
