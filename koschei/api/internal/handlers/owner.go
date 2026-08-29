package handlers

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

type ownerUserRecord struct {
	ID                      string     `json:"id"`
	AuthSubject             string     `json:"auth_subject"`
	Email                   string     `json:"email"`
	WalletAddress           string     `json:"wallet_address,omitempty"`
	Credits                 int        `json:"credits"`
	Status                  string     `json:"status"`
	CreatedAt               time.Time  `json:"created_at"`
	UpdatedAt               time.Time  `json:"updated_at"`
	BannedAt                *time.Time `json:"banned_at,omitempty"`
	PlanID                  *string    `json:"plan_id"`
	ActiveEntitlementStatus string     `json:"active_entitlement_status"`
	EntitlementExpiresAt    *time.Time `json:"entitlement_expires_at"`
	LegacyCredits           int        `json:"legacy_credits"`
}

type ownerCreditInput struct {
	Email         string `json:"email"`
	AuthSubject   string `json:"auth_subject"`
	WalletAddress string `json:"wallet_address"`
	Credits       int    `json:"credits"`
	Reason        string `json:"reason"`
}

type ownerBanInput struct {
	Email       string `json:"email"`
	AuthSubject string `json:"auth_subject"`
	Ban         bool   `json:"ban"`
	Reason      string `json:"reason"`
}

type ownerCommandInput struct {
	Command string         `json:"command"`
	Args    map[string]any `json:"args"`
}

type ownerEmergencyInput struct {
	Key     string `json:"key"`
	Enabled bool   `json:"enabled"`
	Reason  string `json:"reason"`
}

type ownerBrainInput struct {
	Message string `json:"message"`
}

type ownerLoginInput struct {
	Wallet string `json:"wallet"`
	Secret string `json:"secret"`
}

type ownerRemoveInput struct {
	Email         string `json:"email"`
	AuthSubject   string `json:"auth_subject"`
	WalletAddress string `json:"wallet_address"`
	Reason        string `json:"reason"`
}

func (h *Handler) OwnerLogin(w http.ResponseWriter, r *http.Request) {
	ownerWallet := normalizeWallet(firstEnv("OWNER_WALLET", "KOSCHEI_OWNER_WALLET"))
	ownerSecret := strings.TrimSpace(firstEnv("OWNER_SECRET", "KOSCHEI_OWNER_SECRET"))
	if ownerSecret == "" {
		http.NotFound(w, r)
		return
	}
	var req ownerLoginInput
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	if !constantTimeStringEqual(strings.TrimSpace(req.Secret), ownerSecret) {
		http.NotFound(w, r)
		return
	}
	loginWallet := normalizeWallet(req.Wallet)
	if ownerWallet != "" && loginWallet != "" && loginWallet != ownerWallet {
		http.NotFound(w, r)
		return
	}
	secure := strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production")
	http.SetCookie(w, &http.Cookie{Name: "koschei_owner_secret", Value: ownerSecret, Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(12 * time.Hour)})
	http.SetCookie(w, &http.Cookie{Name: "koschei_owner_wallet", Value: firstNonEmpty(ownerWallet, loginWallet), Path: "/", HttpOnly: true, Secure: secure, SameSite: http.SameSiteStrictMode, Expires: time.Now().Add(12 * time.Hour)})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Owner oturumu açıldı."})
}

func (h *Handler) OwnerUsers(w http.ResponseWriter, r *http.Request) {
	if !h.ownerAuth(w, r) {
		return
	}
	if err := ensureOwnerSchema(r.Context(), h.DB); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner schema unavailable"})
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	where := ""
	args := []any{}
	if q != "" {
		where = `WHERE lower(p.email) LIKE $1 OR lower(COALESCE(p.wallet_address,'')) LIKE $1 OR lower(COALESCE(p.auth_subject,'')) LIKE $1`
		args = append(args, "%"+q+"%")
	}
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT p.id::text, COALESCE(p.auth_subject,''), p.email, COALESCE(p.wallet_address,''), COALESCE(p.credits,0), COALESCE(p.status,'active'), p.created_at, p.updated_at, p.banned_at,
		       ent.plan_id, COALESCE(ent.status, 'No active package'), ent.expires_at
		FROM app_user_profiles p
		LEFT JOIN LATERAL (
			SELECT normalize_plan.plan_id, e.status, e.expires_at
			FROM entitlements e
			CROSS JOIN LATERAL (SELECT CASE COALESCE(e.plan_id,'') WHEN 'builder' THEN 'professional' WHEN 'studio' THEN 'enterprise' ELSE COALESCE(e.plan_id,'') END AS plan_id) normalize_plan
			WHERE lower(e.email)=lower(p.email)
			  AND e.status='active'
			  AND COALESCE(e.plan_id,'') <> ''
			  AND COALESCE(e.plan_id,'') <> 'free'
			  AND (e.expires_at IS NULL OR e.expires_at > now())
			ORDER BY e.updated_at DESC, e.created_at DESC
			LIMIT 1
		) ent ON true `+where+` ORDER BY p.created_at DESC LIMIT 500`, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db query failed"})
		return
	}
	defer rows.Close()
	users := []ownerUserRecord{}
	for rows.Next() {
		var u ownerUserRecord
		var planID sql.NullString
		var entitlementStatus string
		var expiresAt sql.NullTime
		if err := rows.Scan(&u.ID, &u.AuthSubject, &u.Email, &u.WalletAddress, &u.Credits, &u.Status, &u.CreatedAt, &u.UpdatedAt, &u.BannedAt, &planID, &entitlementStatus, &expiresAt); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db scan failed"})
			return
		}
		u.LegacyCredits = u.Credits
		if planID.Valid && strings.TrimSpace(planID.String) != "" {
			plan := normalizePackageID(planID.String)
			u.PlanID = &plan
		}
		u.ActiveEntitlementStatus = entitlementStatus
		u.EntitlementExpiresAt = nullTimePtr(expiresAt)
		users = append(users, u)
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "users": users})
}

func (h *Handler) OwnerAddCredits(w http.ResponseWriter, r *http.Request) {
	if !h.ownerAuth(w, r) {
		return
	}
	if err := ensureOwnerSchema(r.Context(), h.DB); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner schema unavailable"})
		return
	}
	var req ownerCreditInput
	if err := decodeJSON(r, &req); err != nil || req.Credits <= 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "positive credits required"})
		return
	}
	reason := strings.TrimSpace(req.Reason)
	if reason == "" {
		reason = "owner_manual_credit"
	}
	where, args := ownerIdentityWhere(req.Email, req.AuthSubject, req.WalletAddress)
	if where == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email, auth_subject, or wallet_address required"})
		return
	}
	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db transaction failed"})
		return
	}
	defer tx.Rollback()
	args = append(args, req.Credits)
	res, err := tx.ExecContext(r.Context(), `UPDATE app_user_profiles SET credits=COALESCE(credits,0)+$`+fmt.Sprint(len(args))+`, updated_at=now() `+where, args...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "credit update failed"})
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	identityArgs := args[:len(args)-1]
	var eventEmail string
	if err := tx.QueryRowContext(r.Context(), `SELECT email FROM app_user_profiles `+where+` LIMIT 1`, identityArgs...).Scan(&eventEmail); err == nil {
		_, _ = tx.ExecContext(r.Context(), `INSERT INTO credit_events (email, amount, reason, event_type) VALUES (lower($1), $2, $3, 'owner_manual_credit')`, eventEmail, req.Credits, reason)
	}
	if err := tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db commit failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "credits_added": req.Credits})
}

func (h *Handler) OwnerBanUser(w http.ResponseWriter, r *http.Request) {
	if !h.ownerAuth(w, r) {
		return
	}
	if err := ensureOwnerSchema(r.Context(), h.DB); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner schema unavailable"})
		return
	}
	var req ownerBanInput
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	where, args := ownerIdentityWhere(req.Email, req.AuthSubject, "")
	if where == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email or auth_subject required"})
		return
	}
	status := "active"
	bannedAt := "NULL"
	if req.Ban {
		status = "banned"
		bannedAt = "now()"
	}
	res, err := h.DB.ExecContext(r.Context(), `UPDATE app_user_profiles SET status=$`+fmt.Sprint(len(args)+1)+`, banned_at=`+bannedAt+`, ban_reason=$`+fmt.Sprint(len(args)+2)+`, updated_at=now() `+where, append(args, status, strings.TrimSpace(req.Reason))...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "user update failed"})
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": status})
}

func (h *Handler) OwnerRemoveUser(w http.ResponseWriter, r *http.Request) {
	if !h.ownerAuth(w, r) {
		return
	}
	if err := ensureOwnerSchema(r.Context(), h.DB); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner schema unavailable"})
		return
	}
	var req ownerRemoveInput
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	where, args := ownerIdentityWhere(req.Email, req.AuthSubject, req.WalletAddress)
	if where == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email, auth_subject, or wallet_address required"})
		return
	}
	res, err := h.DB.ExecContext(r.Context(), `UPDATE app_user_profiles SET status='removed', banned_at=now(), ban_reason=$`+fmt.Sprint(len(args)+1)+`, updated_at=now() `+where, append(args, firstNonEmpty(req.Reason, "owner_removed"))...)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "user remove failed"})
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "user not found"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "removed"})
}

func (h *Handler) OwnerCommand(w http.ResponseWriter, r *http.Request) {
	if !h.ownerAuth(w, r) {
		return
	}
	if err := ensureOwnerSchema(r.Context(), h.DB); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner schema unavailable"})
		return
	}
	var req ownerCommandInput
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Command) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "command required"})
		return
	}
	command := strings.TrimSpace(req.Command)
	status, output, result := h.executeOwnerBrainCommand(r.Context(), command, req.Args)
	if _, err := h.DB.ExecContext(r.Context(), `INSERT INTO ai_command_logs (command, output, status, created_at) VALUES ($1,$2,$3,now())`, command, output, status); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "command log failed"})
		return
	}
	_ = h.recordOwnerBrainEvent(r.Context(), "brain_command", command+" → "+status, status, result)
	code := http.StatusOK
	if status == "error" || status == "unsupported" {
		code = http.StatusBadRequest
	}
	writeJSON(w, code, map[string]any{"ok": status != "error" && status != "unsupported", "status": status, "output": output, "result": result})
}

func (h *Handler) OwnerEmergencyControl(w http.ResponseWriter, r *http.Request) {
	if !h.ownerAuth(w, r) {
		return
	}
	if err := ensureOwnerSchema(r.Context(), h.DB); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner schema unavailable"})
		return
	}
	var req ownerEmergencyInput
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	key := normalizeOwnerControlKey(req.Key)
	if key == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown_control"})
		return
	}
	_, err := h.DB.ExecContext(r.Context(), `
		INSERT INTO owner_system_controls (key, enabled, reason, updated_at)
		VALUES ($1,$2,$3,now())
		ON CONFLICT (key) DO UPDATE SET enabled=EXCLUDED.enabled, reason=EXCLUDED.reason, updated_at=now()`, key, req.Enabled, strings.TrimSpace(req.Reason))
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "control update failed"})
		return
	}
	_ = h.recordOwnerBrainEvent(r.Context(), "emergency_control", fmt.Sprintf("%s set to %t", key, req.Enabled), "active", map[string]any{"key": key, "enabled": req.Enabled})
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "key": key, "enabled": req.Enabled})
}

func (h *Handler) OwnerBrain(w http.ResponseWriter, r *http.Request) {
	if !h.ownerAuth(w, r) {
		return
	}
	if err := ensureOwnerSchema(r.Context(), h.DB); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"success": false, "code": "OWNER_SCHEMA_UNAVAILABLE", "message": "Owner schema unavailable.", "data": nil})
		return
	}
	var req ownerBrainInput
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.Message) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"success": false, "code": "MESSAGE_REQUIRED", "message": "Komut mesajı gerekli.", "data": nil})
		return
	}
	message := strings.TrimSpace(req.Message)
	intent, result, humanMessage, ok := h.routeOwnerBrainCommand(r.Context(), message)
	status := "completed"
	code := "OK"
	if !ok {
		status = "unsupported"
		code = "COMMAND_UNSUPPORTED"
		humanMessage = "Bu komut henüz desteklenmiyor."
	}
	_, _ = h.DB.ExecContext(r.Context(), `INSERT INTO ai_command_logs (command, output, status, created_at) VALUES ($1,$2,$3,now())`, message, humanMessage, status)
	if !ok {
		writeJSON(w, http.StatusOK, map[string]any{"success": false, "code": code, "message": humanMessage, "data": nil})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "code": code, "message": humanMessage, "data": map[string]any{"intent": intent, "result": result}})
}

func (h *Handler) OwnerHealth(w http.ResponseWriter, r *http.Request) {
	if !h.ownerAuth(w, r) {
		return
	}
	dbStatus := "connected"
	if err := h.DB.PingContext(r.Context()); err != nil {
		dbStatus = "error"
	}
	services := map[string]any{
		"database": map[string]string{"status": dbStatus},
		"openai":   map[string]string{"status": configuredStatus("OPENAI_API_KEY")},
		"paddle":   map[string]string{"status": configuredStatus("PADDLE_API_KEY", "PADDLE_WEBHOOK_SECRET", "PADDLE_ENV")},
		"alchemy":  map[string]string{"status": configuredStatusAny("ALCHEMY_API_KEY", "SOLANA_RPC_URL")},
		"github":   map[string]string{"status": configuredStatus("GITHUB_TOKEN", "GITHUB_OWNER", "GITHUB_REPO")},
		"neon":     map[string]string{"status": configuredStatus("DATABASE_URL")},
	}
	writeJSON(w, http.StatusOK, map[string]any{"success": true, "services": services})
}

func (h *Handler) routeOwnerBrainCommand(ctx context.Context, message string) (string, map[string]any, string, bool) {
	cmd := strings.ToLower(strings.TrimSpace(message))
	cmd = strings.Join(strings.Fields(cmd), " ")
	switch {
	case strings.Contains(cmd, "son 24 saat") && strings.Contains(cmd, "hata"):
		result := h.ownerRecentErrors(ctx)
		return "recent_errors_24h", result, "Son 24 saat hata özeti hazır.", true
	case strings.HasPrefix(cmd, "kullanıcı ara") || strings.HasPrefix(cmd, "kullanici ara"):
		email := strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(cmd, "kullanıcı ara"), "kullanici ara"))
		result := h.ownerSearchUser(ctx, email)
		return "user_search", result, "Kullanıcı arama sonucu hazır.", true
	case strings.Contains(cmd, "bekleyen ödeme") || strings.Contains(cmd, "bekleyen odeme"):
		result := h.ownerPendingPayments(ctx)
		return "pending_payments", result, "Bekleyen ödemeler listelendi.", true
	case strings.Contains(cmd, "paddle") && strings.Contains(cmd, "durum"):
		return "paddle_status", envConfiguredResult([]string{"PADDLE_API_KEY", "PADDLE_WEBHOOK_SECRET", "PADDLE_ENV"}, false), "Paddle yapılandırma durumu hazır.", true
	case strings.Contains(cmd, "openai") && strings.Contains(cmd, "durum"):
		return "openai_status", envConfiguredResult([]string{"OPENAI_API_KEY"}, false), "OpenAI yapılandırma durumu hazır.", true
	case strings.Contains(cmd, "alchemy") && strings.Contains(cmd, "durum"):
		return "alchemy_status", envConfiguredResult([]string{"ALCHEMY_API_KEY", "SOLANA_RPC_URL"}, true), "Alchemy / Solana RPC yapılandırma durumu hazır.", true
	case strings.Contains(cmd, "github") && strings.Contains(cmd, "durum"):
		return "github_status", envConfiguredResult([]string{"GITHUB_TOKEN", "GITHUB_OWNER", "GITHUB_REPO"}, false), "GitHub yapılandırma durumu hazır.", true
	case strings.Contains(cmd, "neon") && strings.Contains(cmd, "durum"):
		return "neon_status", envConfiguredResult([]string{"DATABASE_URL"}, false), "Neon veritabanı yapılandırma durumu hazır.", true
	default:
		return "unsupported", nil, "", false
	}
}

func (h *Handler) ownerRecentErrors(ctx context.Context) map[string]any {
	result := map[string]any{}
	if ownerTableExists(ctx, h.DB, "runtime_logs") {
		result["runtime_logs"] = ownerQueryRows(ctx, h.DB, `SELECT created_at, level, message FROM runtime_logs WHERE created_at >= now() - interval '24 hours' AND lower(level) IN ('error','fatal','warn','warning') ORDER BY created_at DESC LIMIT 50`, []string{"created_at", "level", "message"})
	}
	if ownerTableExists(ctx, h.DB, "model_route_logs") {
		result["api_logs"] = ownerQueryRows(ctx, h.DB, `SELECT created_at, provider, model, status, tool FROM model_route_logs WHERE created_at >= now() - interval '24 hours' AND lower(COALESCE(status,'')) NOT IN ('ok','success','completed') ORDER BY created_at DESC LIMIT 50`, []string{"created_at", "provider", "model", "status", "tool"})
	}
	if ownerTableExists(ctx, h.DB, "generation_jobs") {
		result["failed_jobs"] = ownerQueryRows(ctx, h.DB, `SELECT created_at, updated_at, email, tool, provider, status FROM generation_jobs WHERE updated_at >= now() - interval '24 hours' AND lower(status) IN ('failed','error') ORDER BY updated_at DESC LIMIT 50`, []string{"created_at", "updated_at", "email", "tool", "provider", "status"})
	}
	if ownerTableExists(ctx, h.DB, "web3_jobs") {
		result["failed_web3_jobs"] = ownerQueryRows(ctx, h.DB, `SELECT queued_at, updated_at, email, job_type, status, error_code, error_message FROM web3_jobs WHERE updated_at >= now() - interval '24 hours' AND lower(status) IN ('failed','error') ORDER BY updated_at DESC LIMIT 50`, []string{"queued_at", "updated_at", "email", "job_type", "status", "error_code", "error_message"})
	}
	if ownerTableExists(ctx, h.DB, "payment_requests") {
		result["failed_payments"] = ownerQueryRows(ctx, h.DB, `SELECT created_at, reviewed_at, email, product_id, amount_try, currency, status FROM payment_requests WHERE created_at >= now() - interval '24 hours' AND lower(status) IN ('failed','rejected','error') ORDER BY created_at DESC LIMIT 50`, []string{"created_at", "reviewed_at", "email", "product_id", "amount_try", "currency", "status"})
	}
	return result
}

func (h *Handler) ownerSearchUser(ctx context.Context, email string) map[string]any {
	result := map[string]any{"email": email, "user": nil, "entitlement": map[string]any{"active": false}}
	if email == "" || !ownerTableExists(ctx, h.DB, "app_user_profiles") {
		return result
	}
	rows := ownerQueryRows(ctx, h.DB, `SELECT email, COALESCE(auth_subject,''), COALESCE(status,'active'), COALESCE(plan_id,''), COALESCE(credits,0), created_at, updated_at FROM app_user_profiles WHERE lower(email)=lower($1) LIMIT 1`, []string{"email", "auth_subject", "status", "plan_id", "credits_legacy", "created_at", "updated_at"}, email)
	if len(rows) > 0 {
		result["user"] = rows[0]
	}
	if ownerTableExists(ctx, h.DB, "entitlements") {
		rows = ownerQueryRows(ctx, h.DB, `SELECT plan_id, status, created_at AS starts_at, NULL::timestamptz AS expires_at FROM entitlements WHERE lower(email)=lower($1) AND status='active' ORDER BY updated_at DESC, created_at DESC LIMIT 1`, []string{"plan_id", "status", "starts_at", "expires_at"}, email)
		if len(rows) > 0 {
			rows[0]["active"] = true
			result["entitlement"] = rows[0]
		}
	}
	return result
}

func (h *Handler) ownerPendingPayments(ctx context.Context) map[string]any {
	if !ownerTableExists(ctx, h.DB, "payment_requests") {
		return map[string]any{"payment_requests": []map[string]any{}, "table_exists": false}
	}
	rows := ownerQueryRows(ctx, h.DB, `SELECT id::text, email, COALESCE(full_name,''), COALESCE(product_id,''), COALESCE(amount_try,0), COALESCE(currency,'TRY'), status, created_at FROM payment_requests WHERE status='pending' ORDER BY created_at DESC LIMIT 100`, []string{"id", "email", "full_name", "product_id", "amount_try", "currency", "status", "created_at"})
	return map[string]any{"payment_requests": rows, "count": len(rows), "table_exists": true}
}

func configuredStatus(keys ...string) string {
	for _, key := range keys {
		if strings.TrimSpace(os.Getenv(key)) == "" {
			return "missing"
		}
	}
	return "configured"
}

func configuredStatusAny(keys ...string) string {
	for _, key := range keys {
		if strings.TrimSpace(os.Getenv(key)) != "" {
			return "configured"
		}
	}
	return "missing"
}

func envConfiguredResult(keys []string, anyMode bool) map[string]any {
	items := map[string]bool{}
	configuredCount := 0
	for _, key := range keys {
		ok := strings.TrimSpace(os.Getenv(key)) != ""
		items[key] = ok
		if ok {
			configuredCount++
		}
	}
	status := "missing"
	if (!anyMode && configuredCount == len(keys)) || (anyMode && configuredCount > 0) {
		status = "configured"
	}
	return map[string]any{"status": status, "configured": items}
}

func ownerTableExists(ctx context.Context, db *sql.DB, table string) bool {
	var exists bool
	_ = db.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_schema = ANY (current_schemas(false)) AND table_name = $1)`, table).Scan(&exists)
	return exists
}

func ownerQueryRows(ctx context.Context, db *sql.DB, query string, keys []string, args ...any) []map[string]any {
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	items := []map[string]any{}
	vals := make([]any, len(keys))
	ptrs := make([]any, len(keys))
	for i := range vals {
		ptrs[i] = &vals[i]
	}
	for rows.Next() {
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		item := map[string]any{}
		for i, key := range keys {
			item[key] = ownerJSONValue(vals[i])
		}
		items = append(items, item)
	}
	return items
}

func ownerJSONValue(v any) any {
	switch t := v.(type) {
	case nil:
		return nil
	case []byte:
		return string(t)
	case time.Time:
		return t
	default:
		return t
	}
}

func (h *Handler) OwnerStatus(w http.ResponseWriter, r *http.Request) {
	if !h.ownerAuth(w, r) {
		return
	}
	if err := ensureOwnerSchema(r.Context(), h.DB); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "owner schema unavailable"})
		return
	}
	metrics := map[string]any{}
	count := func(key, query string) {
		var v int64
		if err := h.DB.QueryRowContext(r.Context(), query).Scan(&v); err == nil {
			metrics[key] = v
		}
	}
	money := func(key, query string) {
		var v float64
		if err := h.DB.QueryRowContext(r.Context(), query).Scan(&v); err == nil {
			metrics[key] = v
		}
	}
	count("total_users", `SELECT count(*) FROM app_user_profiles`)
	count("active_users_today", `SELECT count(DISTINCT COALESCE(NULLIF(lower(email),''), path)) FROM analytics_events WHERE created_at >= CURRENT_DATE`)
	count("pending_payments", `SELECT count(*) FROM payment_requests WHERE status='pending'`)
	count("approved_payments", `SELECT count(*) FROM payment_requests WHERE status='approved'`)
	money("daily_revenue_try", `SELECT COALESCE(sum(amount_try),0)::float FROM payment_requests WHERE status='approved' AND reviewed_at >= CURRENT_DATE`)
	money("monthly_revenue_try", `SELECT COALESCE(sum(amount_try),0)::float FROM payment_requests WHERE status='approved' AND reviewed_at >= date_trunc('month', now())`)
	money("total_saved_usd", `SELECT COALESCE((SELECT sum(mev_saved_usd) FROM mev_protection_events),0)::float + COALESCE((SELECT sum(loss_prevented_usd) FROM liquidity_drain_alerts),0)::float + COALESCE((SELECT sum(estimated_outflow_usd) FROM proposal_risks WHERE risk_score >= 40),0)::float`)
	count("pending_prs", `SELECT count(*) FROM ai_command_logs WHERE status IN ('queued','running')`)
	var best string
	_ = h.DB.QueryRowContext(r.Context(), `SELECT COALESCE(product_id,'') FROM payment_requests WHERE status='approved' GROUP BY product_id ORDER BY count(*) DESC LIMIT 1`).Scan(&best)
	metrics["best_selling_package"] = best
	logs := []map[string]any{}
	if rows, err := h.DB.QueryContext(r.Context(), `SELECT command, status, output, created_at FROM ai_command_logs ORDER BY created_at DESC LIMIT 100`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var c, s, o string
			var t time.Time
			_ = rows.Scan(&c, &s, &o, &t)
			logs = append(logs, map[string]any{"event": "ai_command", "message": c, "status": s, "output": o, "created_at": t})
		}
	}
	controls := h.ownerSystemControls(r.Context())
	events := h.ownerLiveEvents(r.Context())
	services := h.ownerServiceStatuses(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "metrics": metrics, "logs": logs, "services": services, "controls": controls, "events": events})
}

func (h *Handler) OwnerGrants(w http.ResponseWriter, r *http.Request) {
	if !h.ownerAuth(w, r) {
		return
	}
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT title, deadline, status, COALESCE(notes, '')
		FROM grant_opportunities
		WHERE status <> 'archived'
		ORDER BY fit_score DESC, updated_at DESC
		LIMIT 100`)
	if isMissingRelation(err) {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "grants": []map[string]any{}})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "grants unavailable"})
		return
	}
	defer rows.Close()

	items := make([]map[string]any, 0)
	for rows.Next() {
		var program, deadline, status, focus string
		if err := rows.Scan(&program, &deadline, &status, &focus); err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "grants scan failed"})
			return
		}
		items = append(items, map[string]any{"program": program, "deadline": deadline, "status": status, "focus": focus})
	}
	if err := rows.Err(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "grants unavailable"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "grants": items})
}

func (h *Handler) ShopierWebhook(w http.ResponseWriter, r *http.Request) {
	secret := strings.TrimSpace(firstEnv("SHOPIER_WEBHOOK_SECRET", "OWNER_SECRET"))
	if secret != "" && !constantTimeStringEqual(strings.TrimSpace(r.Header.Get("x-shopier-secret")), secret) {
		http.NotFound(w, r)
		return
	}
	if err := ensureOwnerSchema(r.Context(), h.DB); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "payment schema unavailable"})
		return
	}
	var payload map[string]any
	if err := json.NewDecoder(r.Body).Decode(&payload); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid body"})
		return
	}
	email := lowerStringFromAny(payload["email"])
	productID := strings.ToLower(strings.TrimSpace(fmt.Sprint(payload["product_id"])))
	if email == "" || productID == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email and product_id required"})
		return
	}
	pack, ok := shopierPacks[productID]
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unknown product_id"})
		return
	}
	externalPaymentID := ""
	for _, key := range []string{"payment_id", "order_id", "id"} {
		if value, ok := payload[key]; ok {
			if candidate := strings.TrimSpace(fmt.Sprint(value)); candidate != "" && candidate != "<nil>" {
				externalPaymentID = candidate
				break
			}
		}
	}
	if externalPaymentID == "" {
		externalPaymentID = "shopier:" + email + ":" + productID + ":" + fmt.Sprint(payload["created_at"])
	}
	raw, _ := json.Marshal(payload)
	_, err := h.DB.ExecContext(r.Context(), `INSERT INTO payment_requests (email, full_name, product_id, amount_try, currency, status, raw_payload, payment_provider, external_payment_id, reviewed_at, created_at) VALUES ($1,$2,$3,$4,'TRY','approved',$5::jsonb,'shopier',$6,now(),now())`, email, strings.TrimSpace(fmt.Sprint(payload["full_name"])), productID, pack.AmountTRY, string(raw), externalPaymentID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "webhook insert failed"})
		return
	}
	result, err := h.activatePackageEntitlement(r.Context(), email, productID, "shopier", externalPaymentID)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "entitlement activation failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": "approved", "activated": result.Activated})
}

func (h *Handler) executeOwnerBrainCommand(ctx context.Context, command string, args map[string]any) (string, string, map[string]any) {
	lc := strings.ToLower(strings.TrimSpace(command))
	switch {
	case strings.Contains(lc, "son 24") && strings.Contains(lc, "hata"):
		return h.ownerRecentErrorsCommand(ctx)
	case strings.Contains(lc, "github") && strings.Contains(lc, "son commit"):
		return ownerGitHubLatestCommit(ctx)
	case strings.Contains(lc, "github") && strings.Contains(lc, "deploy"):
		return ownerTriggerDeploy(ctx)
	case strings.Contains(lc, "github") && strings.Contains(lc, "branch"):
		branch := firstNonEmpty(stringArg(args, "branch"), lastField(command))
		if branch == "oluştur" || branch == "olustur" || branch == "branch" {
			branch = ""
		}
		return ownerGitHubCreateBranch(ctx, branch)
	case strings.Contains(lc, "github") && (strings.Contains(lc, "pr") || strings.Contains(lc, "pull request")):
		return ownerGitHubCreatePR(ctx, stringArg(args, "title"), stringArg(args, "branch"), stringArg(args, "body"))
	case strings.Contains(lc, "kullanıcı ara") || strings.Contains(lc, "kullanici ara"):
		email := firstNonEmpty(stringArg(args, "email"), afterColon(command))
		return h.ownerFindUser(ctx, email)
	case strings.Contains(lc, "banlı kullanıcı") || strings.Contains(lc, "banli kullanıcı") || strings.Contains(lc, "banli kullanici"):
		return h.ownerListBannedUsers(ctx)
	case strings.Contains(lc, "banla"):
		email := firstNonEmpty(stringArg(args, "email"), afterColon(command), lastField(command))
		if email == "banla" || !strings.Contains(email, "@") {
			email = stringArg(args, "email")
		}
		return h.ownerSetUserStatus(ctx, email, true)
	case strings.Contains(lc, "kredi ekle"):
		email := stringArg(args, "email")
		credits := intArg(args, "credits")
		return h.ownerAddCreditsCommand(ctx, email, credits)
	case strings.Contains(lc, "paketi değiştir") || strings.Contains(lc, "paketi degistir"):
		return h.ownerChangePackage(ctx, stringArg(args, "email"), stringArg(args, "package"))
	case strings.Contains(lc, "kullanıcı olarak giriş") || strings.Contains(lc, "kullanici olarak giris"):
		return h.ownerCreateImpersonationToken(ctx, stringArg(args, "email"))
	case strings.Contains(lc, "bugünkü gelir") || strings.Contains(lc, "bugunku gelir"):
		return h.ownerRevenue(ctx, "today")
	case strings.Contains(lc, "aylık gelir") || strings.Contains(lc, "aylik gelir"):
		return h.ownerRevenue(ctx, "month")
	case strings.Contains(lc, "paddle") && strings.Contains(lc, "webhook"):
		return h.ownerPaddleSummary(ctx)
	case strings.Contains(lc, "openai") && strings.Contains(lc, "maliyet"):
		return h.ownerOpenAISummary(ctx)
	case strings.Contains(lc, "alchemy"):
		return ownerAlchemyStatus(ctx)
	case strings.Contains(lc, "neon") && strings.Contains(lc, "backup"):
		return h.ownerCreateNeonBackupMarker(ctx)
	default:
		return "unsupported", "Bu owner komutu için güvenli argümanlar eksik veya komut tanınmadı. Desteklenen komutlardan birini ve gerekli e-posta/branch/paket bilgisini gönder.", map[string]any{"command": command}
	}
}

func (h *Handler) ownerRecentErrorsCommand(ctx context.Context) (string, string, map[string]any) {
	items := []map[string]any{}
	rows, err := h.DB.QueryContext(ctx, `SELECT command, output, status, created_at FROM ai_command_logs WHERE status IN ('error','failed','rejected') AND created_at >= now() - interval '24 hours' ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		return "error", "Son hata kayıtları okunamadı: " + err.Error(), nil
	}
	defer rows.Close()
	for rows.Next() {
		var c, o, s string
		var t time.Time
		_ = rows.Scan(&c, &o, &s, &t)
		items = append(items, map[string]any{"message": c, "detail": o, "status": s, "created_at": t})
	}
	return "completed", fmt.Sprintf("Son 24 saatte %d hata kaydı bulundu.", len(items)), map[string]any{"errors": items}
}

func (h *Handler) ownerFindUser(ctx context.Context, email string) (string, string, map[string]any) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "error", "Kullanıcı aramak için mail gerekli.", nil
	}
	rows, err := h.DB.QueryContext(ctx, `SELECT id::text, COALESCE(auth_subject,''), email, COALESCE(wallet_address,''), COALESCE(credits,0), COALESCE(status,'active'), created_at, updated_at, banned_at FROM app_user_profiles WHERE lower(email) LIKE lower($1) ORDER BY created_at DESC LIMIT 20`, "%"+email+"%")
	if err != nil {
		return "error", "Kullanıcı araması başarısız: " + err.Error(), nil
	}
	defer rows.Close()
	users := []ownerUserRecord{}
	for rows.Next() {
		var u ownerUserRecord
		_ = rows.Scan(&u.ID, &u.AuthSubject, &u.Email, &u.WalletAddress, &u.Credits, &u.Status, &u.CreatedAt, &u.UpdatedAt, &u.BannedAt)
		users = append(users, u)
	}
	return "completed", fmt.Sprintf("%d kullanıcı bulundu.", len(users)), map[string]any{"users": users}
}

func (h *Handler) ownerSetUserStatus(ctx context.Context, email string, ban bool) (string, string, map[string]any) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "error", "Ban işlemi için email gerekli.", nil
	}
	status := "active"
	bannedAt := "NULL"
	if ban {
		status = "banned"
		bannedAt = "now()"
	}
	res, err := h.DB.ExecContext(ctx, `UPDATE app_user_profiles SET status=$1, banned_at=`+bannedAt+`, ban_reason='central_brain', updated_at=now() WHERE lower(email)=lower($2)`, status, email)
	if err != nil {
		return "error", "Kullanıcı durumu güncellenemedi: " + err.Error(), nil
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return "error", "Kullanıcı bulunamadı.", nil
	}
	return "completed", "Kullanıcı durumu güncellendi: " + status, map[string]any{"email": email, "status": status}
}

func (h *Handler) ownerAddCreditsCommand(ctx context.Context, email string, credits int) (string, string, map[string]any) {
	if strings.TrimSpace(email) == "" || credits <= 0 {
		return "error", "Kredi eklemek için email ve pozitif credits gerekli.", nil
	}
	res, err := h.DB.ExecContext(ctx, `UPDATE app_user_profiles SET credits=COALESCE(credits,0)+$1, updated_at=now() WHERE lower(email)=lower($2)`, credits, email)
	if err != nil {
		return "error", "Kredi güncellemesi başarısız: " + err.Error(), nil
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		return "error", "Kullanıcı bulunamadı.", nil
	}
	_, _ = h.DB.ExecContext(ctx, `INSERT INTO credit_events (email, amount, reason, event_type) VALUES ($1,$2,'central_brain','owner_credit')`, email, credits)
	return "completed", fmt.Sprintf("%s kullanıcısına %d kredi eklendi.", email, credits), map[string]any{"email": email, "credits": credits}
}

func (h *Handler) ownerChangePackage(ctx context.Context, email, pack string) (string, string, map[string]any) {
	email = strings.TrimSpace(email)
	pack = normalizePlanTier(pack)
	if email == "" || pack == "" {
		return "error", "Paket değiştirmek için email ve package gerekli.", nil
	}
	res, err := h.activatePackageEntitlement(ctx, email, pack, "owner_manual", "central-brain-"+fmt.Sprint(time.Now().UnixNano()))
	if err != nil {
		return "error", "Paket değiştirilemedi: " + err.Error(), nil
	}
	return "completed", "Kullanıcı paketi güncellendi: " + pack, map[string]any{"email": email, "package": pack, "activated": res.Activated}
}

func (h *Handler) ownerCreateImpersonationToken(ctx context.Context, email string) (string, string, map[string]any) {
	email = strings.TrimSpace(email)
	if email == "" {
		return "error", "Kullanıcı olarak giriş için email gerekli.", nil
	}
	token := generateID() + generateID() + generateID()
	_, err := h.DB.ExecContext(ctx, `INSERT INTO owner_impersonation_tokens (token, email, expires_at, created_at) VALUES ($1,$2,now()+interval '10 minutes',now())`, token, email)
	if err != nil {
		return "error", "Impersonation token oluşturulamadı: " + err.Error(), nil
	}
	return "completed", "10 dakika geçerli owner impersonation token üretildi. Customer dashboard bunu görmez; sadece owner akışında kullanılmalıdır.", map[string]any{"email": email, "token": token, "expires_in_seconds": 600}
}

func (h *Handler) ownerRevenue(ctx context.Context, period string) (string, string, map[string]any) {
	query := `SELECT COALESCE(count(*),0), COALESCE(sum(amount_try),0)::float FROM payment_requests WHERE status='approved' AND reviewed_at >= CURRENT_DATE`
	if period == "month" {
		query = `SELECT COALESCE(count(*),0), COALESCE(sum(amount_try),0)::float FROM payment_requests WHERE status='approved' AND reviewed_at >= date_trunc('month', now())`
	}
	var count int64
	var total float64
	if err := h.DB.QueryRowContext(ctx, query).Scan(&count, &total); err != nil {
		return "error", "Gelir okunamadı: " + err.Error(), nil
	}
	return "completed", fmt.Sprintf("%s gelir: %.2f TRY / %d ödeme", period, total, count), map[string]any{"period": period, "payments": count, "revenue_try": total}
}

func (h *Handler) ownerPaddleSummary(ctx context.Context) (string, string, map[string]any) {
	var pending int64
	var total float64
	_ = h.DB.QueryRowContext(ctx, `SELECT count(*) FROM payment_requests WHERE payment_provider='paddle' AND status='pending'`).Scan(&pending)
	_ = h.DB.QueryRowContext(ctx, `SELECT COALESCE(sum(amount_try),0)::float FROM payment_requests WHERE payment_provider='paddle' AND status='approved'`).Scan(&total)
	configured := strings.TrimSpace(os.Getenv("PADDLE_API_KEY")) != ""
	webhook := strings.TrimSpace(os.Getenv("PADDLE_WEBHOOK_SECRET")) != ""
	return "completed", "Paddle durumu üretildi.", map[string]any{"api_configured": configured, "webhook_secret_configured": webhook, "pending_payments": pending, "total_revenue_try": total, "entitlements": "database-backed"}
}

func (h *Handler) ownerOpenAISummary(ctx context.Context) (string, string, map[string]any) {
	status := ownerHTTPHealth(ctx, "https://api.openai.com/v1/models", "OPENAI_API_KEY")
	return "completed", "OpenAI canlı durum kontrolü tamamlandı. Maliyet detayları OpenAI usage/cost endpoint yetkisi yapılandırıldığında provider API'den genişletilir.", map[string]any{"status": status, "daily_cost": "provider_usage_scope_required", "monthly_cost": "provider_usage_scope_required"}
}

func ownerAlchemyStatus(ctx context.Context) (string, string, map[string]any) {
	status := ownerHTTPHealth(ctx, "https://solana-devnet.g.alchemy.com/v2/"+os.Getenv("ALCHEMY_API_KEY"), "ALCHEMY_API_KEY")
	return "completed", "Alchemy RPC durumu kontrol edildi.", map[string]any{"alchemy": status}
}

func (h *Handler) ownerCreateNeonBackupMarker(ctx context.Context) (string, string, map[string]any) {
	id := "neon-backup-" + fmt.Sprint(time.Now().Unix())
	_, err := h.DB.ExecContext(ctx, `INSERT INTO owner_central_brain_events (event_type, message, status, payload, created_at) VALUES ('neon_backup',$1,'requested',$2::jsonb,now())`, "Neon backup requested", `{"provider":"neon"}`)
	if err != nil {
		return "error", "Neon backup isteği kaydedilemedi: " + err.Error(), nil
	}
	return "completed", "Neon backup isteği kaydedildi. NEON_API_KEY/Project API bağlandığında fiziksel snapshot tetiklenir.", map[string]any{"backup_request_id": id, "status": "requested"}
}

func (h *Handler) ownerListBannedUsers(ctx context.Context) (string, string, map[string]any) {
	rows, err := h.DB.QueryContext(ctx, `SELECT id::text, COALESCE(auth_subject,''), email, COALESCE(wallet_address,''), COALESCE(credits,0), COALESCE(status,'active'), created_at, updated_at, banned_at FROM app_user_profiles WHERE status='banned' ORDER BY banned_at DESC NULLS LAST LIMIT 100`)
	if err != nil {
		return "error", "Banlı kullanıcılar okunamadı: " + err.Error(), nil
	}
	defer rows.Close()
	users := []ownerUserRecord{}
	for rows.Next() {
		var u ownerUserRecord
		_ = rows.Scan(&u.ID, &u.AuthSubject, &u.Email, &u.WalletAddress, &u.Credits, &u.Status, &u.CreatedAt, &u.UpdatedAt, &u.BannedAt)
		users = append(users, u)
	}
	return "completed", fmt.Sprintf("%d banlı kullanıcı listelendi.", len(users)), map[string]any{"users": users}
}

func ownerGitHubLatestCommit(ctx context.Context) (string, string, map[string]any) {
	repo := strings.TrimSpace(os.Getenv("GITHUB_REPO"))
	if repo == "" {
		return "error", "GITHUB_REPO yapılandırılmamış.", nil
	}
	body, code, err := ownerGitHubRequest(ctx, http.MethodGet, "/repos/"+repo+"/commits?per_page=1", nil)
	if err != nil {
		return "error", err.Error(), nil
	}
	if code >= 300 {
		return "error", fmt.Sprintf("GitHub HTTP %d: %s", code, string(body)), nil
	}
	var commits []map[string]any
	_ = json.Unmarshal(body, &commits)
	return "completed", "Github son commit alındı.", map[string]any{"commits": commits}
}

func ownerGitHubCreateBranch(ctx context.Context, branch string) (string, string, map[string]any) {
	repo := strings.TrimSpace(os.Getenv("GITHUB_REPO"))
	branch = strings.TrimSpace(branch)
	if repo == "" || branch == "" {
		return "error", "Branch oluşturmak için GITHUB_REPO ve branch adı gerekli.", nil
	}
	body, code, err := ownerGitHubRequest(ctx, http.MethodGet, "/repos/"+repo+"/git/ref/heads/main", nil)
	if err != nil {
		return "error", err.Error(), nil
	}
	if code >= 300 {
		return "error", fmt.Sprintf("GitHub ref HTTP %d: %s", code, string(body)), nil
	}
	var ref struct {
		Object struct {
			SHA string `json:"sha"`
		} `json:"object"`
	}
	_ = json.Unmarshal(body, &ref)
	payload := map[string]any{"ref": "refs/heads/" + branch, "sha": ref.Object.SHA}
	out, code, err := ownerGitHubRequest(ctx, http.MethodPost, "/repos/"+repo+"/git/refs", payload)
	if err != nil {
		return "error", err.Error(), nil
	}
	if code >= 300 {
		return "error", fmt.Sprintf("GitHub branch HTTP %d: %s", code, string(out)), nil
	}
	return "completed", "GitHub branch oluşturuldu: " + branch, map[string]any{"branch": branch}
}

func ownerGitHubCreatePR(ctx context.Context, title, branch, body string) (string, string, map[string]any) {
	repo := strings.TrimSpace(os.Getenv("GITHUB_REPO"))
	if repo == "" || strings.TrimSpace(branch) == "" {
		return "error", "PR açmak için GITHUB_REPO ve branch gerekli.", nil
	}
	if strings.TrimSpace(title) == "" {
		title = "Koschei Central Brain PR"
	}
	if strings.TrimSpace(body) == "" {
		body = "Opened by Koschei Central Brain."
	}
	payload := map[string]any{"title": title, "head": branch, "base": "main", "body": body}
	out, code, err := ownerGitHubRequest(ctx, http.MethodPost, "/repos/"+repo+"/pulls", payload)
	if err != nil {
		return "error", err.Error(), nil
	}
	if code >= 300 {
		return "error", fmt.Sprintf("GitHub PR HTTP %d: %s", code, string(out)), nil
	}
	var res map[string]any
	_ = json.Unmarshal(out, &res)
	return "completed", "GitHub PR açıldı.", res
}

func ownerTriggerDeploy(ctx context.Context) (string, string, map[string]any) {
	url := strings.TrimSpace(firstEnv("RENDER_DEPLOY_HOOK_URL", "DEPLOY_HOOK_URL"))
	if url == "" {
		return "error", "Render deploy hook URL yapılandırılmamış.", nil
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		return "error", "Deploy tetiklenemedi: " + err.Error(), nil
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode >= 300 {
		return "error", fmt.Sprintf("Deploy hook HTTP %d: %s", resp.StatusCode, string(b)), nil
	}
	return "completed", "Github/Render deploy başlatıldı.", map[string]any{"status_code": resp.StatusCode, "response": string(b)}
}

func ownerGitHubRequest(ctx context.Context, method, path string, payload any) ([]byte, int, error) {
	token := strings.TrimSpace(os.Getenv("GITHUB_TOKEN"))
	if token == "" {
		return nil, 0, errors.New("GITHUB_TOKEN yapılandırılmamış")
	}
	var body io.Reader
	if payload != nil {
		b, _ := json.Marshal(payload)
		body = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "https://api.github.com"+path, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if payload != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := (&http.Client{Timeout: 12 * time.Second}).Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return b, resp.StatusCode, nil
}

func (h *Handler) ownerServiceStatuses(ctx context.Context) []map[string]any {
	services := []map[string]any{
		{"name": "OPENAI", "status": ownerHTTPHealth(ctx, "https://api.openai.com/v1/models", "OPENAI_API_KEY")},
		{"name": "GITHUB", "status": ownerGitHubHealth(ctx)},
		{"name": "NEON", "status": ownerEnvHealth("NEON_API_KEY")},
		{"name": "DATABASE", "status": ownerDBHealth(ctx, h.DB)},
		{"name": "PADDLE", "status": ownerEnvHealth("PADDLE_API_KEY")},
		{"name": "ALCHEMY", "status": ownerEnvHealth("ALCHEMY_API_KEY")},
		{"name": "RENDER", "status": ownerEnvHealth("RENDER_DEPLOY_HOOK_URL")},
	}
	return services
}

func ownerHTTPHealth(ctx context.Context, endpoint, envKey string) map[string]any {
	if strings.TrimSpace(os.Getenv(envKey)) == "" {
		return map[string]any{"state": "Disconnected", "detail": envKey + " missing"}
	}
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	req.Header.Set("Authorization", "Bearer "+os.Getenv(envKey))
	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		return map[string]any{"state": "Timeout", "detail": err.Error()}
	}
	defer resp.Body.Close()
	if resp.StatusCode == 429 {
		return map[string]any{"state": "Rate Limited", "detail": "HTTP 429"}
	}
	if resp.StatusCode >= 400 {
		return map[string]any{"state": "Disconnected", "detail": fmt.Sprintf("HTTP %d", resp.StatusCode)}
	}
	return map[string]any{"state": "Connected", "detail": fmt.Sprintf("HTTP %d", resp.StatusCode)}
}
func ownerGitHubHealth(ctx context.Context) map[string]any {
	if strings.TrimSpace(os.Getenv("GITHUB_TOKEN")) == "" || strings.TrimSpace(os.Getenv("GITHUB_REPO")) == "" {
		return map[string]any{"state": "Disconnected", "detail": "GITHUB_TOKEN or GITHUB_REPO missing"}
	}
	_, code, err := ownerGitHubRequest(ctx, http.MethodGet, "/repos/"+os.Getenv("GITHUB_REPO"), nil)
	if err != nil {
		return map[string]any{"state": "Timeout", "detail": err.Error()}
	}
	if code == 429 || code == 403 {
		return map[string]any{"state": "Rate Limited", "detail": fmt.Sprintf("HTTP %d", code)}
	}
	if code >= 400 {
		return map[string]any{"state": "Disconnected", "detail": fmt.Sprintf("HTTP %d", code)}
	}
	return map[string]any{"state": "Connected", "detail": fmt.Sprintf("HTTP %d", code)}
}
func ownerEnvHealth(key string) map[string]any {
	if strings.TrimSpace(os.Getenv(key)) == "" {
		return map[string]any{"state": "Disconnected", "detail": key + " missing"}
	}
	return map[string]any{"state": "Connected", "detail": "configured"}
}
func ownerDBHealth(ctx context.Context, db *sql.DB) map[string]any {
	if db == nil {
		return map[string]any{"state": "Disconnected", "detail": "db nil"}
	}
	c, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	if err := db.PingContext(c); err != nil {
		return map[string]any{"state": "Timeout", "detail": err.Error()}
	}
	return map[string]any{"state": "Connected", "detail": "ping ok"}
}

func (h *Handler) ownerSystemControls(ctx context.Context) []map[string]any {
	rows, err := h.DB.QueryContext(ctx, `SELECT key, enabled, COALESCE(reason,''), updated_at FROM owner_system_controls ORDER BY key`)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var k, r string
		var e bool
		var t time.Time
		_ = rows.Scan(&k, &e, &r, &t)
		out = append(out, map[string]any{"key": k, "enabled": e, "reason": r, "updated_at": t})
	}
	return out
}
func (h *Handler) ownerLiveEvents(ctx context.Context) []map[string]any {
	rows, err := h.DB.QueryContext(ctx, `SELECT event_type, message, status, payload, created_at FROM owner_central_brain_events ORDER BY created_at DESC LIMIT 50`)
	if err != nil {
		return []map[string]any{}
	}
	defer rows.Close()
	out := []map[string]any{}
	for rows.Next() {
		var typ, msg, st, payload string
		var t time.Time
		_ = rows.Scan(&typ, &msg, &st, &payload, &t)
		out = append(out, map[string]any{"event_type": typ, "message": msg, "status": st, "payload": payload, "created_at": t})
	}
	return out
}
func (h *Handler) recordOwnerBrainEvent(ctx context.Context, typ, msg, status string, payload any) error {
	b, _ := json.Marshal(payload)
	_, err := h.DB.ExecContext(ctx, `INSERT INTO owner_central_brain_events (event_type, message, status, payload, created_at) VALUES ($1,$2,$3,$4::jsonb,now())`, typ, msg, status, string(b))
	return err
}

func normalizeOwnerControlKey(key string) string {
	k := strings.ToLower(strings.TrimSpace(key))
	allowed := map[string]string{"maintenance_mode": "maintenance_mode", "stop_registrations": "stop_registrations", "stop_sales": "stop_sales", "stop_ai_requests": "stop_ai_requests", "api_readonly": "api_readonly", "system_readonly": "system_readonly"}
	return allowed[k]
}
func stringArg(args map[string]any, key string) string {
	if args == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(args[key]))
}
func intArg(args map[string]any, key string) int {
	if args == nil {
		return 0
	}
	switch v := args[key].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		var n int
		fmt.Sscanf(v, "%d", &n)
		return n
	}
	return 0
}
func afterColon(s string) string {
	if i := strings.Index(s, ":"); i >= 0 {
		return strings.TrimSpace(s[i+1:])
	}
	return ""
}
func lastField(s string) string {
	f := strings.Fields(s)
	if len(f) == 0 {
		return ""
	}
	return strings.Trim(f[len(f)-1], " .")
}

func ensureOwnerSchema(ctx context.Context, db *sql.DB) error {
	if db == nil {
		return errors.New("db nil")
	}
	stmts := []string{
		`ALTER TABLE app_user_profiles ADD COLUMN IF NOT EXISTS wallet_address text`,
		`ALTER TABLE app_user_profiles ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active'`,
		`ALTER TABLE app_user_profiles ADD COLUMN IF NOT EXISTS banned_at timestamptz`,
		`ALTER TABLE app_user_profiles ADD COLUMN IF NOT EXISTS ban_reason text`,
		`CREATE TABLE IF NOT EXISTS credit_events (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), email text, amount integer NOT NULL, reason text, event_type text, created_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE TABLE IF NOT EXISTS ai_command_logs (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), command text NOT NULL, output text NOT NULL DEFAULT '', status text NOT NULL DEFAULT 'queued', created_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE TABLE IF NOT EXISTS owner_system_controls (key text PRIMARY KEY, enabled boolean NOT NULL DEFAULT false, reason text NOT NULL DEFAULT '', updated_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE TABLE IF NOT EXISTS owner_central_brain_events (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), event_type text NOT NULL, message text NOT NULL DEFAULT '', status text NOT NULL DEFAULT 'info', payload jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE TABLE IF NOT EXISTS owner_impersonation_tokens (token text PRIMARY KEY, email text NOT NULL, expires_at timestamptz NOT NULL, used_at timestamptz, created_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE TABLE IF NOT EXISTS system_analytics (day date PRIMARY KEY DEFAULT CURRENT_DATE, active_users integer NOT NULL DEFAULT 0, revenue_try numeric NOT NULL DEFAULT 0, credits_consumed integer NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE TABLE IF NOT EXISTS mev_protection_events (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), user_wallet text NOT NULL DEFAULT '', tx_signature text NOT NULL DEFAULT '', estimated_loss_usd numeric NOT NULL DEFAULT 0, mev_saved_usd numeric NOT NULL DEFAULT 0, jito_tip_used boolean NOT NULL DEFAULT false, risk_score integer NOT NULL DEFAULT 0, risk_level text NOT NULL DEFAULT 'DÜŞÜK', route text NOT NULL DEFAULT '', raw_payload jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now())`,
		`ALTER TABLE mev_protection_events ADD COLUMN IF NOT EXISTS mev_saved_usd numeric NOT NULL DEFAULT 0`,
		`ALTER TABLE mev_protection_events ADD COLUMN IF NOT EXISTS raw_payload jsonb NOT NULL DEFAULT '{}'::jsonb`,
		`CREATE TABLE IF NOT EXISTS liquidity_drain_alerts (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), pool_address text NOT NULL DEFAULT '', token_mint text NOT NULL DEFAULT '', severity text NOT NULL DEFAULT 'DÜŞÜK', risk_score integer NOT NULL DEFAULT 0, removed_liquidity_usd numeric NOT NULL DEFAULT 0, loss_prevented_usd numeric NOT NULL DEFAULT 0, telegram_queued boolean NOT NULL DEFAULT false, sms_queued boolean NOT NULL DEFAULT false, created_at timestamptz NOT NULL DEFAULT now())`,
		`CREATE TABLE IF NOT EXISTS proposal_risks (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), dao_id text NOT NULL DEFAULT '', treasury_address text NOT NULL DEFAULT '', proposal_id text NOT NULL DEFAULT '', risk_score integer NOT NULL DEFAULT 0, risk_level text NOT NULL DEFAULT 'DÜŞÜK', estimated_outflow_usd numeric NOT NULL DEFAULT 0, instruction_count integer NOT NULL DEFAULT 0, created_at timestamptz NOT NULL DEFAULT now())`,
	}
	for _, stmt := range stmts {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return err
		}
	}
	return nil
}

func ownerIdentityWhere(email, sub, wallet string) (string, []any) {
	if strings.TrimSpace(email) != "" {
		return "WHERE lower(email)=lower($1)", []any{strings.TrimSpace(email)}
	}
	if strings.TrimSpace(sub) != "" {
		return "WHERE auth_subject=$1", []any{strings.TrimSpace(sub)}
	}
	if strings.TrimSpace(wallet) != "" {
		return "WHERE lower(wallet_address)=lower($1)", []any{strings.TrimSpace(wallet)}
	}
	return "", nil
}

func lowerStringFromAny(v any) string { return strings.ToLower(strings.TrimSpace(fmt.Sprint(v))) }
