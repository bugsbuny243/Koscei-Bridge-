package handlers

import (
	"bytes"
	"io"
	"net/http"
	"strings"
	"time"
)

const maxPasswordResetBody = 64 << 10

func (h *Handler) passwordResetProxy(w http.ResponseWriter, r *http.Request, neonPath string) {
	baseURL := strings.TrimRight(strings.TrimSpace(configuredNeonAuthBaseURL()), "/")
	if baseURL == "" {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "neon_auth_not_configured", "message": "Authentication is temporarily unavailable."})
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, maxPasswordResetBody))
	if err != nil || len(body) == 0 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_request"})
		return
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, baseURL+neonPath, bytes.NewReader(body))
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "auth_request_failed"})
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	if origin := publicBaseURL(r); origin != "" {
		req.Header.Set("Origin", origin)
	}

	resp, err := (&http.Client{Timeout: 10 * time.Second}).Do(req)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "neon_auth_unavailable", "message": "The authentication provider is temporarily unreachable."})
		return
	}
	defer resp.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(resp.StatusCode)
	if len(responseBody) == 0 {
		_, _ = w.Write([]byte("{}"))
		return
	}
	_, _ = w.Write(responseBody)
}
