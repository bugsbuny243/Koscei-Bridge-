package handlers

import (
	"net/http"
	"strings"

	"koschei/api/internal/requestmeta"
	"koschei/api/internal/services"
)

func (h *Handler) OwnerLoginAudited(w http.ResponseWriter, r *http.Request) {
	ownerWallet := normalizeWallet(firstEnv("OWNER_WALLET", "KOSCHEI_OWNER_WALLET"))
	ownerSecret := strings.TrimSpace(firstEnv("OWNER_SECRET", "KOSCHEI_OWNER_SECRET"))
	if ownerSecret == "" {
		services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "owner_login_failed", "owner", "error", map[string]any{"reason": "owner_secret_missing"}))
		http.NotFound(w, r)
		return
	}
	var req ownerLoginInput
	if err := decodeJSON(r, &req); err != nil {
		services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "owner_login_failed", "owner", "warning", map[string]any{"reason": "invalid_body"}))
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	if !constantTimeStringEqual(strings.TrimSpace(req.Secret), ownerSecret) {
		services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "owner_login_failed", "owner", "critical", map[string]any{"reason": "failed_secret"}))
		http.NotFound(w, r)
		return
	}
	loginWallet := normalizeWallet(req.Wallet)
	if ownerWallet != "" && loginWallet != "" && loginWallet != ownerWallet {
		services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "owner_login_failed", "owner", "critical", map[string]any{"reason": "wallet_mismatch"}))
		http.NotFound(w, r)
		return
	}

	sessionWallet := firstNonEmpty(ownerWallet, loginWallet)
	token, expiresAt, err := h.issueOwnerSession(r.Context(), sessionWallet, r)
	if err != nil {
		services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "owner_login_failed", "owner", "error", map[string]any{"reason": "session_issue_failed"}))
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "owner_session_unavailable"})
		return
	}
	setOwnerSessionCookies(w, token, sessionWallet, expiresAt)
	services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "owner_login_success", "owner", "info", map[string]any{"wallet_present": sessionWallet != "", "session_storage": ownerSessionStorageName(h)}))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "message": "Owner oturumu açıldı."})
}

func securityAuditFromRequest(r *http.Request, eventType, actorType, severity string, metadata map[string]any) services.SecurityAuditEvent {
	return services.SecurityAuditEvent{EventType: eventType, ActorType: actorType, IP: requestAuditIP(r), UserAgent: r.UserAgent(), Path: r.URL.Path, Severity: severity, Metadata: metadata}
}

func requestAuditIP(r *http.Request) string {
	return requestmeta.ClientIP(r)
}

func ownerSessionStorageName(h *Handler) string {
	if h != nil && h.DB != nil {
		return "database_hash"
	}
	return "development_memory_hash"
}
