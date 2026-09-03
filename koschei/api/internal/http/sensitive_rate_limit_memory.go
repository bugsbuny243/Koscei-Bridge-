package http

import (
	"errors"
	"strings"
	"sync"
	"time"
)

const sensitiveMemoryBucketMax = 4096

type sensitiveMemoryBucket struct {
	WindowStartedAt time.Time
	ExpiresAt       time.Time
	Count           int64
}

var sensitiveMemoryLimits = struct {
	sync.Mutex
	items map[string]sensitiveMemoryBucket
}{items: map[string]sensitiveMemoryBucket{}}

func consumeMemorySensitiveLimit(keyHash, route string, rule sensitiveLimitRule, now time.Time) (sensitiveLimitDecision, error) {
	keyHash = strings.TrimSpace(keyHash)
	route = strings.TrimSpace(route)
	if keyHash == "" || route == "" || !strings.HasPrefix(route, "/api/") || rule.Limit <= 0 || rule.Window <= 0 || rule.Window > 24*time.Hour {
		return sensitiveLimitDecision{}, errors.New("invalid memory rate limit input")
	}
	if now.IsZero() {
		now = time.Now().UTC()
	}
	bucketKey := keyHash + "\x00" + route

	sensitiveMemoryLimits.Lock()
	defer sensitiveMemoryLimits.Unlock()

	cleanupSensitiveMemoryLimitsLocked(now)
	bucket, exists := sensitiveMemoryLimits.items[bucketKey]
	if !exists || !bucket.ExpiresAt.After(now) {
		bucket = sensitiveMemoryBucket{WindowStartedAt: now, ExpiresAt: now.Add(rule.Window)}
	}
	bucket.Count++
	if len(sensitiveMemoryLimits.items) >= sensitiveMemoryBucketMax && !exists {
		revokeOldestSensitiveMemoryBucketLocked()
	}
	sensitiveMemoryLimits.items[bucketKey] = bucket

	remaining := int64(rule.Limit) - bucket.Count
	if remaining < 0 {
		remaining = 0
	}
	reset := int64(bucket.ExpiresAt.Sub(now).Seconds())
	if reset < 1 {
		reset = 1
	}
	return sensitiveLimitDecision{
		Allowed:           bucket.Count <= int64(rule.Limit),
		Count:             bucket.Count,
		Limit:             rule.Limit,
		Remaining:         remaining,
		ResetAfterSeconds: reset,
	}, nil
}

func cleanupSensitiveMemoryLimitsLocked(now time.Time) {
	for key, bucket := range sensitiveMemoryLimits.items {
		if !bucket.ExpiresAt.After(now) {
			delete(sensitiveMemoryLimits.items, key)
		}
	}
}

func revokeOldestSensitiveMemoryBucketLocked() {
	oldestKey := ""
	var oldest time.Time
	for key, bucket := range sensitiveMemoryLimits.items {
		if oldestKey == "" || bucket.ExpiresAt.Before(oldest) {
			oldestKey = key
			oldest = bucket.ExpiresAt
		}
	}
	if oldestKey != "" {
		delete(sensitiveMemoryLimits.items, oldestKey)
	}
}
