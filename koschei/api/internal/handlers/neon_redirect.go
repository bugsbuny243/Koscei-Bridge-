package handlers

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type neonAuthState struct {
	Redirect string `json:"redirect"`
	Nonce    string `json:"nonce"`
	Sig      string `json:"sig"`
}

// NeonLogin redirects users to the Neon Auth hosted login page.
func (h *Handler) NeonLogin(w http.ResponseWriter, r *http.Request) {
	h.redirectToNeonAuth(w, r, "login")
}

// NeonRegister redirects users to the Neon Auth hosted registration page.
func (h *Handler) NeonRegister(w http.ResponseWriter, r *http.Request) {
	h.redirectToNeonAuth(w, r, "register")
}

func (h *Handler) redirectToNeonAuth(w http.ResponseWriter, r *http.Request, action string) {
	baseURL := strings.TrimRight(configuredNeonAuthBaseURL(), "/")
	if baseURL == "" {
		http.Error(w, "NEON_AUTH_BASE_URL is not configured", http.StatusInternalServerError)
		return
	}

	redirectTo := sanitizeFrontendRedirect(r.URL.Query().Get("redirect"))
	if redirectTo == "" {
		redirectTo = "/hub.html"
	}

	state, err := h.newNeonAuthState(redirectTo)
	if err != nil {
		http.Error(w, "failed to create auth state", http.StatusInternalServerError)
		return
	}

	callbackURL := absolutePublicURL(r, "/api/auth/neon-callback")
	authURL, err := url.Parse(baseURL + "/" + action)
	if err != nil {
		http.Error(w, "NEON_AUTH_BASE_URL is invalid", http.StatusInternalServerError)
		return
	}
	q := authURL.Query()
	q.Set("redirect_uri", callbackURL)
	q.Set("state", state)
	if audience := strings.TrimSpace(os.Getenv("NEON_AUTH_AUDIENCE")); audience != "" {
		q.Set("audience", audience)
	}
	authURL.RawQuery = q.Encode()

	http.Redirect(w, r, authURL.String(), http.StatusTemporaryRedirect)
}

func (h *Handler) newNeonAuthState(redirectTo string) (string, error) {
	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return "", err
	}
	state := neonAuthState{
		Redirect: redirectTo,
		Nonce:    base64.RawURLEncoding.EncodeToString(nonceBytes),
	}
	state.Sig = h.signNeonAuthState(state.Redirect, state.Nonce)
	stateBytes, err := json.Marshal(state)
	if err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(stateBytes), nil
}

func (h *Handler) parseNeonAuthState(encoded string) (string, bool) {
	stateBytes, err := base64.RawURLEncoding.DecodeString(encoded)
	if err != nil {
		return "", false
	}
	var state neonAuthState
	if err := json.Unmarshal(stateBytes, &state); err != nil {
		return "", false
	}
	if state.Redirect == "" || state.Nonce == "" || state.Sig == "" {
		return "", false
	}
	if !hmac.Equal([]byte(state.Sig), []byte(h.signNeonAuthState(state.Redirect, state.Nonce))) {
		return "", false
	}
	redirectTo := sanitizeFrontendRedirect(state.Redirect)
	return redirectTo, redirectTo != ""
}

func (h *Handler) signNeonAuthState(redirectTo, nonce string) string {
	mac := hmac.New(sha256.New, []byte(h.neonAuthStateSecret()))
	_, _ = mac.Write([]byte(redirectTo))
	_, _ = mac.Write([]byte("\x00"))
	_, _ = mac.Write([]byte(nonce))
	return base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
}

func (h *Handler) neonAuthStateSecret() string {
	for _, value := range []string{
		os.Getenv("NEON_AUTH_STATE_SECRET"),
		os.Getenv("KOSCHEI_AUTH_STATE_SECRET"),
		os.Getenv("USER_SESSION_SECRET"),
		os.Getenv("OWNER_SECRET"),
		os.Getenv("KOSCHEI_OWNER_SECRET"),
		h.AdminPassword,
		os.Getenv("DATABASE_URL"),
	} {
		if strings.TrimSpace(value) != "" {
			return value
		}
	}
	return "koschei-dev-neon-auth-state-secret"
}

func sanitizeFrontendRedirect(value string) string {
	parsed, err := url.Parse(strings.TrimSpace(value))
	if err != nil || parsed.IsAbs() || parsed.Host != "" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return ""
	}
	switch parsed.Path {
	case "/", "/hub", "/hub.html":
		return "/hub.html"
	case "/dashboard", "/dashboard.html":
		return "/dashboard.html"
	case "/account", "/account.html":
		return "/account.html"
	case "/scan", "/scan.html":
		return "/scan.html"
	case "/pricing", "/pricing.html":
		return "/pricing.html"
	default:
		return ""
	}
}

// getScheme returns the public request scheme behind Render or another proxy.
func getScheme(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Proto")); forwarded != "" {
		return strings.ToLower(strings.TrimSpace(strings.Split(forwarded, ",")[0]))
	}
	if r.TLS != nil {
		return "https"
	}
	return "http"
}

func getHost(r *http.Request) string {
	if forwarded := strings.TrimSpace(r.Header.Get("X-Forwarded-Host")); forwarded != "" {
		return strings.TrimSpace(strings.Split(forwarded, ",")[0])
	}
	return r.Host
}

// This file builds Neon hosted-UI redirects and signs the callback state without creating custom JWTs.
