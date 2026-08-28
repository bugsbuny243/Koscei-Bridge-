package http

import (
	"context"
	"database/sql"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func sharedRateLimitTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", "postgres://postgres:postgres@127.0.0.1:5432/koschei_ci?sslmode=disable")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	db.SetMaxOpenConns(12)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		_ = db.Close()
		t.Skipf("postgres unavailable: %v", err)
	}
	return db
}

func TestSensitiveRuleForLiveRiskBadgeRoute(t *testing.T) {
	rule, ok := sensitiveRuleForPath("/api/v1/risk/badge")
	if !ok {
		t.Fatal("live risk badge route is not rate limited")
	}
	if rule.Limit != 20 {
		t.Fatalf("risk badge limit = %d, want 20", rule.Limit)
	}
	if rule.Window != time.Minute {
		t.Fatalf("risk badge window = %s, want %s", rule.Window, time.Minute)
	}
}

func TestSensitiveRuleKeepsLegacyRiskBadgeAlias(t *testing.T) {
	if _, ok := sensitiveRuleForPath("/api/v1/security/risk-badge"); !ok {
		t.Fatal("legacy risk badge alias should remain rate limited")
	}
}

func TestSensitiveRuleCoversTransactionGuard(t *testing.T) {
	rule, ok := sensitiveRuleForPath("/api/v1/shield/transaction")
	if !ok || rule.Limit != 30 || rule.Window != time.Minute {
		t.Fatalf("transaction guard rate limit = %+v ok=%v", rule, ok)
	}
}

func TestSensitiveRuleCoversCustomerStateRecheck(t *testing.T) {
	rule, ok := sensitiveRuleForPath("/api/customer/web3/transaction-state-recheck")
	if !ok || rule.Limit != 30 || rule.Window != time.Minute {
		t.Fatalf("customer state recheck IP rate limit = %+v ok=%v", rule, ok)
	}
}

func TestCustomerStateRecheckRateLimitFailsClosedWithoutAuthenticatedSubject(t *testing.T) {
	called := false
	handler := customerStateRecheckRateLimit(nil, func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "https://tradepigloball.co/api/customer/web3/transaction-state-recheck", nil))
	if recorder.Code != http.StatusUnauthorized || called {
		t.Fatalf("unauthenticated customer recheck rate limiter status=%d called=%v", recorder.Code, called)
	}
}

func TestConsumeSharedSensitiveLimitIsAtomicAcrossPools(t *testing.T) {
	dbOne := sharedRateLimitTestDB(t)
	defer dbOne.Close()
	dbTwo := sharedRateLimitTestDB(t)
	defer dbTwo.Close()

	route := "/api/v1/shield/transaction"
	keyHash := sensitiveBucketKeyHash(fmt.Sprintf("2001:db8::%x", time.Now().UnixNano()), route)
	cleanupSharedRateLimitTestBucket(t, dbOne, keyHash, route)
	defer cleanupSharedRateLimitTestBucket(t, dbOne, keyHash, route)

	rule := sensitiveLimitRule{Limit: 5, Window: time.Minute}
	const requests = 20
	var allowed atomic.Int64
	var maxCount atomic.Int64
	var wg sync.WaitGroup
	errorsCh := make(chan error, requests)
	for index := 0; index < requests; index++ {
		wg.Add(1)
		go func(index int) {
			defer wg.Done()
			db := dbOne
			if index%2 == 1 {
				db = dbTwo
			}
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			decision, err := consumeSharedSensitiveLimit(ctx, db, keyHash, route, rule)
			if err != nil {
				errorsCh <- err
				return
			}
			if decision.Allowed {
				allowed.Add(1)
			}
			for {
				current := maxCount.Load()
				if decision.Count <= current || maxCount.CompareAndSwap(current, decision.Count) {
					break
				}
			}
		}(index)
	}
	wg.Wait()
	close(errorsCh)
	for err := range errorsCh {
		t.Fatalf("shared rate limit request failed: %v", err)
	}
	if allowed.Load() != int64(rule.Limit) {
		t.Fatalf("allowed requests = %d, want exactly %d", allowed.Load(), rule.Limit)
	}
	if maxCount.Load() != requests {
		t.Fatalf("maximum shared request count = %d, want %d", maxCount.Load(), requests)
	}
}

func TestConsumeSharedSensitiveLimitResetsExpiredWindow(t *testing.T) {
	db := sharedRateLimitTestDB(t)
	defer db.Close()
	route := "/api/auth/login"
	keyHash := sensitiveBucketKeyHash(fmt.Sprintf("expired-%d", time.Now().UnixNano()), route)
	cleanupSharedRateLimitTestBucket(t, db, keyHash, route)
	defer cleanupSharedRateLimitTestBucket(t, db, keyHash, route)

	_, err := db.Exec(`INSERT INTO security_rate_limit_buckets
		(bucket_key_hash,route,window_started_at,window_seconds,request_count,expires_at)
		VALUES($1,$2,statement_timestamp()-interval '2 minutes',60,99,statement_timestamp()-interval '1 minute')`, keyHash, route)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	decision, err := consumeSharedSensitiveLimit(ctx, db, keyHash, route, sensitiveLimitRule{Limit: 1, Window: time.Minute})
	if err != nil {
		t.Fatal(err)
	}
	if !decision.Allowed || decision.Count != 1 || decision.Remaining != 0 || decision.ResetAfterSeconds < 1 {
		t.Fatalf("expired bucket did not reset atomically: %+v", decision)
	}
}

func TestSensitiveRateLimitMiddlewareSharesLimitAndHeaders(t *testing.T) {
	dbOne := sharedRateLimitTestDB(t)
	defer dbOne.Close()
	dbTwo := sharedRateLimitTestDB(t)
	defer dbTwo.Close()
	setSecurityAuditDB(nil)

	route := "/api/owner/login"
	clientIP := "2001:db8::657"
	keyHash := sensitiveBucketKeyHash(clientIP, route)
	cleanupSharedRateLimitTestBucket(t, dbOne, keyHash, route)
	defer cleanupSharedRateLimitTestBucket(t, dbOne, keyHash, route)

	var downstream atomic.Int64
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		downstream.Add(1)
		w.WriteHeader(http.StatusNoContent)
	})
	firstInstance := sensitiveRateLimit(dbOne, next)
	secondInstance := sensitiveRateLimit(dbTwo, next)
	for index := 1; index <= 6; index++ {
		recorder := httptest.NewRecorder()
		request := httptest.NewRequest(http.MethodPost, "https://tradepigloball.co"+route, strings.NewReader(`{}`))
		request.RemoteAddr = "[" + clientIP + "]:43123"
		handler := firstInstance
		if index%2 == 0 {
			handler = secondInstance
		}
		handler.ServeHTTP(recorder, request)
		if recorder.Header().Get("RateLimit-Limit") != "5" || recorder.Header().Get("RateLimit-Reset") == "" {
			t.Fatalf("request %d missing shared rate limit headers: %#v", index, recorder.Header())
		}
		if index <= 5 && recorder.Code != http.StatusNoContent {
			t.Fatalf("request %d status = %d, want %d", index, recorder.Code, http.StatusNoContent)
		}
		if index == 6 {
			if recorder.Code != http.StatusTooManyRequests {
				t.Fatalf("sixth request status = %d, want %d", recorder.Code, http.StatusTooManyRequests)
			}
			if recorder.Header().Get("Retry-After") == "" || recorder.Header().Get("RateLimit-Remaining") != "0" {
				t.Fatalf("denied request missing retry headers: %#v", recorder.Header())
			}
		}
	}
	if downstream.Load() != 5 {
		t.Fatalf("downstream calls = %d, want 5", downstream.Load())
	}
}

func TestSensitiveRateLimitFailsClosedWithoutDatabase(t *testing.T) {
	setSecurityAuditDB(nil)
	called := false
	handler := sensitiveRateLimit(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "https://tradepigloball.co/api/auth/login", nil))
	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want fail-closed %d", recorder.Code, http.StatusServiceUnavailable)
	}
	if called {
		t.Fatal("sensitive downstream handler ran without the shared rate limit database")
	}
	if recorder.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After = %q, want 1", recorder.Header().Get("Retry-After"))
	}
}

func TestSensitiveRateLimitBypassesOrdinaryRouteWithoutDatabase(t *testing.T) {
	called := false
	handler := sensitiveRateLimit(nil, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	}))
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "https://tradepigloball.co/api/version", nil))
	if recorder.Code != http.StatusNoContent || !called {
		t.Fatalf("ordinary route was blocked: status=%d called=%v", recorder.Code, called)
	}
}

func TestSensitiveBucketKeyHashDoesNotExposeClientIP(t *testing.T) {
	hash := sensitiveBucketKeyHash("203.0.113.99", "/api/auth/login")
	if !strings.HasPrefix(hash, "sha256:") || len(hash) != len("sha256:")+64 {
		t.Fatalf("unexpected bucket hash: %s", hash)
	}
	if strings.Contains(hash, "203.0.113.99") {
		t.Fatal("bucket key exposed the raw client IP")
	}
	if hash != sensitiveBucketKeyHash("203.0.113.99", "/api/auth/login") {
		t.Fatal("bucket key hash is not deterministic")
	}
}

func cleanupSharedRateLimitTestBucket(t *testing.T, db *sql.DB, keyHash, route string) {
	t.Helper()
	if _, err := db.Exec(`DELETE FROM security_rate_limit_buckets WHERE bucket_key_hash=$1 AND route=$2`, keyHash, route); err != nil {
		t.Fatalf("cleanup shared rate limit bucket: %v", err)
	}
}
