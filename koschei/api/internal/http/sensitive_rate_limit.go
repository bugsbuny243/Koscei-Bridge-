package http

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"koschei/api/internal/services"
)

const sharedSensitiveLimitTimeout = 2 * time.Second

var sharedSensitiveLimitNextCleanup atomic.Int64

type sensitiveLimitRule struct {
	Limit  int
	Window time.Duration
}

type sensitiveLimitDecision struct {
	Allowed           bool
	Count             int64
	Limit             int
	Remaining         int64
	ResetAfterSeconds int64
}

func sensitiveRateLimit(db *sql.DB, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rule, ok := sensitiveRuleForPath(r.URL.Path)
		if !ok {
			next.ServeHTTP(w, r)
			return
		}

		clientIP := securityClientIP(r)
		keyHash := sensitiveBucketKeyHash(clientIP, r.URL.Path)
		ctx, cancel := context.WithTimeout(r.Context(), sharedSensitiveLimitTimeout)
		decision, err := consumeSharedSensitiveLimit(ctx, db, keyHash, r.URL.Path, rule)
		cancel()
		if err != nil {
			setSensitiveRateLimitHeaders(w, sensitiveLimitDecision{Limit: rule.Limit, Remaining: 0, ResetAfterSeconds: 1})
			w.Header().Set("Retry-After", "1")
			services.WriteSecurityAuditEvent(r.Context(), getSecurityAuditDB(), services.SecurityAuditEvent{
				EventType: "rate_limit_unavailable", ActorType: "request", IP: clientIP, UserAgent: r.UserAgent(),
				Path: r.URL.Path, Severity: "error", Metadata: map[string]any{"fail_closed": true, "reason": sharedSensitiveLimitErrorClass(err)},
			})
			writeSecurityJSON(w, http.StatusServiceUnavailable, map[string]string{
				"error": "rate_limit_unavailable", "message": "Request protection is temporarily unavailable. Please try again.",
			})
			return
		}

		setSensitiveRateLimitHeaders(w, decision)
		if !decision.Allowed {
			w.Header().Set("Retry-After", strconv.FormatInt(maxSensitiveResetSeconds(decision.ResetAfterSeconds), 10))
			services.WriteSecurityAuditEvent(r.Context(), getSecurityAuditDB(), services.SecurityAuditEvent{
				EventType: "rate_limit_exceeded", ActorType: "request", IP: clientIP, UserAgent: r.UserAgent(),
				Path: r.URL.Path, Severity: "warning", Metadata: map[string]any{
					"limit": rule.Limit, "window_seconds": int(rule.Window.Seconds()), "request_count": decision.Count,
					"reset_after_seconds": decision.ResetAfterSeconds, "shared_store": "postgresql",
				},
			})
			writeSecurityJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limit_exceeded", "message": "Too many requests. Please try again later."})
			return
		}

		maybeCleanupSharedSensitiveLimits(db)
		next.ServeHTTP(w, r)
	})
}

func sensitiveRuleForPath(path string) (sensitiveLimitRule, bool) {
	path = strings.TrimSpace(path)
	switch path {
	case "/api/owner/login":
		return sensitiveLimitRule{Limit: 5, Window: 15 * time.Minute}, true
	case "/api/auth/login", "/api/auth/register":
		return sensitiveLimitRule{Limit: 10, Window: 10 * time.Minute}, true
	case "/api/auth/wallet/challenge", "/api/auth/wallet/verify":
		return sensitiveLimitRule{Limit: 10, Window: 5 * time.Minute}, true
	case "/api/arvis/preflight":
		return sensitiveLimitRule{Limit: 30, Window: time.Minute}, true
	case "/api/token/scan", "/api/public/transaction-simulate":
		return sensitiveLimitRule{Limit: 10, Window: time.Minute}, true
	case "/api/v1/radar/check", "/api/v1/unified/analyze":
		return sensitiveLimitRule{Limit: 30, Window: time.Minute}, true
	case "/api/v1/scan/token", "/api/v1/shield/preflight", "/api/v1/shield/transaction", "/api/v1/shield/address-poisoning":
		return sensitiveLimitRule{Limit: 30, Window: time.Minute}, true
	case "/api/v1/risk/badge", "/api/v1/security/risk-badge":
		return sensitiveLimitRule{Limit: 20, Window: time.Minute}, true
	case "/api/paddle/webhook", "/api/v1/paddle/webhook", "/api/shopier/webhook":
		return sensitiveLimitRule{Limit: 120, Window: time.Minute}, true
	case "/api/paddle/checkout":
		return sensitiveLimitRule{Limit: 20, Window: 5 * time.Minute}, true
	default:
		return sensitiveLimitRule{}, false
	}
}

func consumeSharedSensitiveLimit(ctx context.Context, db *sql.DB, keyHash, route string, rule sensitiveLimitRule) (sensitiveLimitDecision, error) {
	if db == nil {
		return sensitiveLimitDecision{}, errors.New("rate limit database unavailable")
	}
	keyHash = strings.TrimSpace(keyHash)
	route = strings.TrimSpace(route)
	windowSeconds := int(rule.Window / time.Second)
	if keyHash == "" || route == "" || !strings.HasPrefix(route, "/api/") || rule.Limit <= 0 || windowSeconds <= 0 || windowSeconds > 86400 {
		return sensitiveLimitDecision{}, errors.New("invalid shared rate limit input")
	}

	const query = `
WITH current_window AS (
    SELECT to_timestamp(
        floor(extract(epoch FROM statement_timestamp()) / $3::double precision) * $3::double precision
    ) AS window_started_at
), consumed AS (
    INSERT INTO security_rate_limit_buckets
        (bucket_key_hash, route, window_started_at, window_seconds, request_count, expires_at, updated_at)
    SELECT $1, $2, window_started_at, $3, 1,
           window_started_at + ($3 * interval '1 second'), statement_timestamp()
    FROM current_window
    ON CONFLICT (bucket_key_hash, route) DO UPDATE SET
        window_started_at = CASE
            WHEN security_rate_limit_buckets.expires_at <= statement_timestamp()
              OR security_rate_limit_buckets.window_seconds <> EXCLUDED.window_seconds
            THEN EXCLUDED.window_started_at
            ELSE security_rate_limit_buckets.window_started_at
        END,
        window_seconds = EXCLUDED.window_seconds,
        request_count = CASE
            WHEN security_rate_limit_buckets.expires_at <= statement_timestamp()
              OR security_rate_limit_buckets.window_seconds <> EXCLUDED.window_seconds
            THEN 1
            ELSE security_rate_limit_buckets.request_count + 1
        END,
        expires_at = CASE
            WHEN security_rate_limit_buckets.expires_at <= statement_timestamp()
              OR security_rate_limit_buckets.window_seconds <> EXCLUDED.window_seconds
            THEN EXCLUDED.expires_at
            ELSE security_rate_limit_buckets.expires_at
        END,
        updated_at = statement_timestamp()
    RETURNING request_count, expires_at
)
SELECT request_count <= $4,
       request_count,
       GREATEST(1, ceil(extract(epoch FROM (expires_at - statement_timestamp())))::bigint)
FROM consumed`

	decision := sensitiveLimitDecision{Limit: rule.Limit}
	if err := db.QueryRowContext(ctx, query, keyHash, route, windowSeconds, rule.Limit).Scan(
		&decision.Allowed, &decision.Count, &decision.ResetAfterSeconds,
	); err != nil {
		return sensitiveLimitDecision{}, err
	}
	remaining := int64(rule.Limit) - decision.Count
	if remaining < 0 {
		remaining = 0
	}
	decision.Remaining = remaining
	return decision, nil
}

func sensitiveBucketKeyHash(clientIP, route string) string {
	clientIP = strings.TrimSpace(clientIP)
	if clientIP == "" {
		clientIP = "unknown"
	}
	digest := sha256.Sum256([]byte(clientIP + "\x00" + strings.TrimSpace(route)))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func setSensitiveRateLimitHeaders(w http.ResponseWriter, decision sensitiveLimitDecision) {
	w.Header().Set("RateLimit-Limit", strconv.Itoa(decision.Limit))
	w.Header().Set("RateLimit-Remaining", strconv.FormatInt(decision.Remaining, 10))
	w.Header().Set("RateLimit-Reset", strconv.FormatInt(maxSensitiveResetSeconds(decision.ResetAfterSeconds), 10))
	w.Header().Set("X-RateLimit-Limit", strconv.Itoa(decision.Limit))
	w.Header().Set("X-RateLimit-Remaining", strconv.FormatInt(decision.Remaining, 10))
	w.Header().Set("X-RateLimit-Reset", strconv.FormatInt(maxSensitiveResetSeconds(decision.ResetAfterSeconds), 10))
}

func maxSensitiveResetSeconds(value int64) int64 {
	if value < 1 {
		return 1
	}
	return value
}

func sharedSensitiveLimitErrorClass(err error) string {
	if err == nil {
		return "unknown"
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		return "timeout"
	}
	if strings.Contains(strings.ToLower(err.Error()), "database unavailable") {
		return "database_unavailable"
	}
	return "database_error"
}

func maybeCleanupSharedSensitiveLimits(db *sql.DB) {
	if db == nil {
		return
	}
	now := time.Now().Unix()
	next := sharedSensitiveLimitNextCleanup.Load()
	if now < next || !sharedSensitiveLimitNextCleanup.CompareAndSwap(next, now+300) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), sharedSensitiveLimitTimeout)
	defer cancel()
	_, _ = db.ExecContext(ctx, `DELETE FROM security_rate_limit_buckets WHERE expires_at < statement_timestamp() - interval '1 hour'`)
}
