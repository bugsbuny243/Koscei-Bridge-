package http

import (
	"context"
	"testing"
	"time"
)

func TestSensitiveRateLimitUsesBoundedMemoryInNeonAuthOnlyMode(t *testing.T) {
	t.Setenv("KOSCHEI_NEON_AUTH_ONLY", "true")
	sensitiveMemoryLimits.Lock()
	sensitiveMemoryLimits.items = map[string]sensitiveMemoryBucket{}
	sensitiveMemoryLimits.Unlock()

	rule := sensitiveLimitRule{Limit: 2, Window: time.Minute}
	key := sensitiveBucketKeyHash("203.0.113.9", "/api/owner/login")
	first, err := consumeSharedSensitiveLimit(context.Background(), nil, key, "/api/owner/login", rule)
	if err != nil || !first.Allowed || first.Remaining != 1 {
		t.Fatalf("first decision=%+v err=%v", first, err)
	}
	second, err := consumeSharedSensitiveLimit(context.Background(), nil, key, "/api/owner/login", rule)
	if err != nil || !second.Allowed || second.Remaining != 0 {
		t.Fatalf("second decision=%+v err=%v", second, err)
	}
	third, err := consumeSharedSensitiveLimit(context.Background(), nil, key, "/api/owner/login", rule)
	if err != nil || third.Allowed || third.Count != 3 {
		t.Fatalf("third decision=%+v err=%v", third, err)
	}
}

func TestSensitiveRateLimitStillFailsClosedWithoutDatabaseOutsideAuthOnlyMode(t *testing.T) {
	t.Setenv("KOSCHEI_NEON_AUTH_ONLY", "false")
	rule := sensitiveLimitRule{Limit: 2, Window: time.Minute}
	key := sensitiveBucketKeyHash("203.0.113.10", "/api/owner/login")
	if _, err := consumeSharedSensitiveLimit(context.Background(), nil, key, "/api/owner/login", rule); err == nil {
		t.Fatal("expected database-unavailable error outside auth-only mode")
	}
}
