package handlers

import "net/http"

func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	h.memberEmailPasswordProxy(w, r, "/sign-up/email")
}

func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Query().Get("action") {
	case "request_password_reset":
		h.passwordResetProxy(w, r, "/request-password-reset")
		return
	case "reset_password":
		h.passwordResetProxy(w, r, "/reset-password")
		return
	default:
		h.memberEmailPasswordProxy(w, r, "/sign-in/email")
	}
}

// Me confirms the already-verified Neon Auth identity installed by RequireAuth.
// Authentication must not depend on Koschei application persistence: a valid
// Neon session remains valid even when the stateless Web3 runtime has no DB.
func (h *Handler) Me(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"user": map[string]any{
			"id":           claims.Sub,
			"auth_subject": claims.Sub,
			"email":        claims.Email,
			"role":         "member",
		},
	})
}
