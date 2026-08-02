package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type apiPrincipal struct {
	KeyID              string
	AuthSubject        string
	Email              string
	RateLimitPerMinute int
	MonthlyLimit       int
}

type apiPrincipalContextKey struct{}

type createAPIKeyRequest struct {
	Name               string `json:"name"`
	MonthlyLimit       int    `json:"monthly_limit"`
	RateLimitPerMinute int    `json:"rate_limit_per_minute"`
}

func (h *Handler) CreateAPIKey(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req createAPIKeyRequest
	_ = decodeJSON(r, &req)
	name := strings.TrimSpace(req.Name)
	if name == "" {
		name = "Varsayılan API Anahtarı"
	}

	requestedMonthly := req.MonthlyLimit
	requestedRPM := req.RateLimitPerMinute
	evaluation, evaluationErr := h.evaluateTokenAccess(r.Context(), claims.Sub)
	tier := apiKeyEffectiveTier(evaluation, evaluationErr)
	caps := apiKeyCapsForTier(tier)
	effectiveMonthly, effectiveRPM := clampAPIKeyLimits(requestedMonthly, requestedRPM, caps)

	raw, err := newRawAPIKey()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "key_generation_failed"})
		return
	}
	prefix := raw
	if len(prefix) > 18 {
		prefix = prefix[:18]
	}
	hash := hashAPIKey(raw)
	var id string
	if err := h.DB.QueryRowContext(r.Context(), `
		INSERT INTO api_keys (auth_subject,email,name,key_prefix,key_hash,monthly_limit,monthly_quota,rate_limit_per_minute)
		VALUES ($1,lower($2),$3,$4,$5,$6,$6,$7)
		RETURNING id::text`, claims.Sub, claims.Email, name, prefix, hash, effectiveMonthly, effectiveRPM).Scan(&id); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "api_key_created", "customer", "info", map[string]any{
		"api_key_id":                      id,
		"name":                            name,
		"tier":                            tier,
		"requested_monthly_limit":         requestedMonthly,
		"requested_rate_limit_per_minute": requestedRPM,
		"monthly_limit":                   effectiveMonthly,
		"rate_limit_per_minute":           effectiveRPM,
	}))
	writeJSON(w, http.StatusCreated, map[string]any{
		"id":                    id,
		"name":                  name,
		"key":                   raw,
		"tier":                  tier,
		"monthly_limit":         effectiveMonthly,
		"rate_limit_per_minute": effectiveRPM,
		"warning":               "Bu anahtar sadece şimdi gösterilir.",
	})
}

func (h *Handler) ListAPIKeys(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	rows, err := h.DB.QueryContext(r.Context(), `SELECT id::text,name,key_prefix,status,monthly_limit,rate_limit_per_minute,created_at,last_used_at,revoked_at FROM api_keys WHERE auth_subject=$1 ORDER BY created_at DESC`, claims.Sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var id, name, prefix, status string
		var monthly, rpm int
		var created time.Time
		var last, revoked sql.NullTime
		if err := rows.Scan(&id, &name, &prefix, &status, &monthly, &rpm, &created, &last, &revoked); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
			return
		}
		items = append(items, map[string]any{"id": id, "name": name, "key_prefix": prefix, "status": status, "monthly_limit": monthly, "rate_limit_per_minute": rpm, "created_at": created, "last_used_at": nullableTime(last), "revoked_at": nullableTime(revoked)})
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "title": "API Anahtarları", "api_keys": items})
}

func (h *Handler) RevokeAPIKey(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/account/api-keys/")
	id = strings.TrimSuffix(id, "/revoke")
	res, err := h.DB.ExecContext(r.Context(), `UPDATE api_keys SET status='revoked', revoked_at=now() WHERE id=$1 AND auth_subject=$2 AND status='active'`, id, claims.Sub)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	rows, _ := res.RowsAffected()
	if rows == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "api_key_not_found"})
		return
	}
	services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "api_key_revoked", "customer", "info", map[string]any{"api_key_id": id}))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "API anahtarı iptal edildi."})
}

func (h *Handler) APIUsage(w http.ResponseWriter, r *http.Request) {
	p, ok := apiPrincipalFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if requestID := strings.TrimSpace(r.URL.Query().Get("request_id")); requestID != "" {
		h.apiUsageRequestResult(w, r, p, requestID)
		return
	}

	includeResults := strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("include_results")), "1") || strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("include_results")), "true")
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT request_id::text,endpoint,status,credits_reserved,credits_charged,COALESCE(error_code,''),latency_ms,metadata,COALESCE(idempotency_key,''),created_at,completed_at
		FROM api_usage_events
		WHERE api_key_id=$1
		ORDER BY created_at DESC
		LIMIT 100`, p.KeyID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	defer rows.Close()
	items := []map[string]any{}
	for rows.Next() {
		var rid, endpoint, status, code, idempotencyKey string
		var reserved, charged int
		var latency sql.NullInt64
		var metadata []byte
		var created time.Time
		var completed sql.NullTime
		if err := rows.Scan(&rid, &endpoint, &status, &reserved, &charged, &code, &latency, &metadata, &idempotencyKey, &created, &completed); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
			return
		}
		item := map[string]any{
			"request_id":       rid,
			"endpoint":         endpoint,
			"status":           status,
			"credits_reserved": reserved,
			"credits_charged":  charged,
			"error_code":       code,
			"latency_ms":       nullableInt64(latency),
			"idempotency_key":  idempotencyKey,
			"result_available": usageResultAvailable(metadata),
			"created_at":       created,
			"completed_at":     nullableTime(completed),
			"result_url":       "/api/v1/usage?request_id=" + rid,
		}
		if includeResults {
			item["result"] = decodeUsageMetadata(metadata)
		}
		items = append(items, item)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "title": "API Kullanım Geçmişi", "usage": items})
}

func (h *Handler) apiUsageRequestResult(w http.ResponseWriter, r *http.Request, p apiPrincipal, requestID string) {
	var rid, endpoint, status, code, idempotencyKey string
	var reserved, charged int
	var latency sql.NullInt64
	var metadata []byte
	var created time.Time
	var completed sql.NullTime
	err := h.DB.QueryRowContext(r.Context(), `
		SELECT request_id::text,endpoint,status,credits_reserved,credits_charged,COALESCE(error_code,''),latency_ms,metadata,COALESCE(idempotency_key,''),created_at,completed_at
		FROM api_usage_events
		WHERE api_key_id=$1 AND request_id::text=$2
		LIMIT 1`, p.KeyID, requestID).
		Scan(&rid, &endpoint, &status, &reserved, &charged, &code, &latency, &metadata, &idempotencyKey, &created, &completed)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "request_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	terminal := status == "completed" || status == "refunded" || status == "failed"
	response := map[string]any{
		"ok":               true,
		"request_id":       rid,
		"endpoint":         endpoint,
		"status":           status,
		"terminal":         terminal,
		"credits_reserved": reserved,
		"credits_charged":  charged,
		"error_code":       code,
		"latency_ms":       nullableInt64(latency),
		"idempotency_key":  idempotencyKey,
		"result_available": usageResultAvailable(metadata),
		"result":           decodeUsageMetadata(metadata),
		"created_at":       created,
		"completed_at":     nullableTime(completed),
	}
	if !terminal {
		response["poll_after_ms"] = 1500
	}
	writeJSON(w, http.StatusOK, response)
}

func decodeUsageMetadata(raw []byte) any {
	if len(raw) == 0 || string(raw) == "null" {
		return map[string]any{}
	}
	var value any
	if err := json.Unmarshal(raw, &value); err != nil {
		return map[string]any{}
	}
	return value
}

func usageResultAvailable(raw []byte) bool {
	trimmed := strings.TrimSpace(string(raw))
	return trimmed != "" && trimmed != "{}" && trimmed != "null"
}

func nullableInt64(value sql.NullInt64) any {
	if value.Valid {
		return value.Int64
	}
	return nil
}

func (h *Handler) APIKeyAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := strings.TrimSpace(r.Header.Get("X-API-Key"))
		if raw == "" {
			raw = bearerToken(r.Header.Get("Authorization"))
		}
		if raw == "" {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "missing_api_key"})
			return
		}
		var p apiPrincipal
		err := h.DB.QueryRowContext(r.Context(), `SELECT id::text,auth_subject,email,rate_limit_per_minute,COALESCE(monthly_quota, monthly_limit) FROM api_keys WHERE key_hash=$1 AND status='active'`, hashAPIKey(raw)).Scan(&p.KeyID, &p.AuthSubject, &p.Email, &p.RateLimitPerMinute, &p.MonthlyLimit)
		if err != nil {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_api_key"})
			return
		}
		p = clampAPIPrincipalToAbsoluteCaps(p)
		_, _ = h.DB.ExecContext(r.Context(), `UPDATE api_keys SET last_used_at=now() WHERE id=$1`, p.KeyID)
		r = r.WithContext(context.WithValue(r.Context(), apiPrincipalContextKey{}, p))
		if !h.enforceAPIAccessPolicy(w, r, p) {
			return
		}
		next(w, r)
	}
}

func (h *Handler) APIRateLimit(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		p, ok := apiPrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		limit := p.RateLimitPerMinute
		if limit <= 0 {
			limit = 60
		}
		if h.Limiter != nil && !h.Limiter.allow("api:"+p.KeyID+":"+r.URL.Path, limit, time.Minute) {
			writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limit_exceeded", "message": "Kullanım limiti aşıldı."})
			return
		}
		next(w, r)
	}
}

func (h *Handler) reserveAPICredits(ctx context.Context, p apiPrincipal, endpoint, requestID string, cost int) error {
	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE app_user_profiles SET credits=credits-$1, updated_at=now() WHERE auth_subject=$2 AND credits >= $1`, cost, p.AuthSubject)
	if err != nil {
		return err
	}
	rows, _ := res.RowsAffected()
	if rows != 1 {
		return errors.New("insufficient credits")
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO api_usage_events (api_key_id,auth_subject,email,endpoint,request_id,credits_reserved,status) VALUES ($1,$2,lower($3),$4,$5,$6,'reserved')`, p.KeyID, p.AuthSubject, p.Email, endpoint, requestID, cost); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO api_credit_ledger (api_key_id,auth_subject,email,amount,event_type,reason,request_id) VALUES ($1,$2,lower($3),$4,'reserve',$5,$6)`, p.KeyID, p.AuthSubject, p.Email, -cost, endpoint, requestID); err != nil {
		return err
	}
	return tx.Commit()
}

func (h *Handler) finalizeAPIUsage(ctx context.Context, requestID string, latencyMS int) {
	_, _ = h.DB.ExecContext(ctx, `UPDATE api_usage_events SET status='completed', credits_charged=credits_reserved, latency_ms=$1, completed_at=now() WHERE request_id=$2 AND status='reserved'`, latencyMS, requestID)
}

func (h *Handler) refundAPICredits(ctx context.Context, requestID, code string) {
	tx, err := h.DB.BeginTx(ctx, nil)
	if err != nil {
		return
	}
	defer tx.Rollback()
	var p apiPrincipal
	var reserved int
	if err := tx.QueryRowContext(ctx, `SELECT api_key_id::text,auth_subject,email,credits_reserved FROM api_usage_events WHERE request_id=$1 AND status='reserved' FOR UPDATE`, requestID).Scan(&p.KeyID, &p.AuthSubject, &p.Email, &reserved); err != nil {
		return
	}
	_, _ = tx.ExecContext(ctx, `UPDATE app_user_profiles SET credits=credits+$1, updated_at=now() WHERE auth_subject=$2`, reserved, p.AuthSubject)
	_, _ = tx.ExecContext(ctx, `UPDATE api_usage_events SET status='refunded', error_code=$1, completed_at=now() WHERE request_id=$2`, code, requestID)
	_, _ = tx.ExecContext(ctx, `INSERT INTO api_credit_ledger (api_key_id,auth_subject,email,amount,event_type,reason,request_id) VALUES ($1,$2,lower($3),$4,'refund',$5,$6)`, p.KeyID, p.AuthSubject, p.Email, reserved, code, requestID)
	_ = tx.Commit()
}

func apiPrincipalFromContext(ctx context.Context) (apiPrincipal, bool) {
	p, ok := ctx.Value(apiPrincipalContextKey{}).(apiPrincipal)
	return p, ok
}

func bearerToken(h string) string {
	h = strings.TrimSpace(h)
	if strings.HasPrefix(strings.ToLower(h), "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func hashAPIKey(raw string) string {
	pepper := os.Getenv("API_KEY_PEPPER")
	sum := sha256.Sum256([]byte(raw + pepper))
	return hex.EncodeToString(sum[:])
}

func newRawAPIKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "kch_live_" + base64.RawURLEncoding.EncodeToString(b), nil
}

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:]), nil
}

func nullableTime(t sql.NullTime) any {
	if t.Valid {
		return t.Time
	}
	return nil
}

func (h *Handler) APIKeysCollection(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		h.ListAPIKeys(w, r)
	case http.MethodPost:
		h.CreateAPIKey(w, r)
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
