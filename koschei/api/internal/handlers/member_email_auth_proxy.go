package handlers

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type memberEmailAuthRequest struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	Name        string `json:"name"`
	CallbackURL string `json:"callbackURL"`
}

type memberNeonAuthResult struct {
	StatusCode int
	Data       map[string]any
	Body       []byte
	Token      string
	TokenFound bool
}

func (h *Handler) memberEmailPasswordProxy(w http.ResponseWriter, r *http.Request, neonPath string) {
	var request memberEmailAuthRequest
	if err := decodeJSON(r, &request); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_json"})
		return
	}
	request.Email = strings.ToLower(strings.TrimSpace(request.Email))
	if request.Email == "" || strings.TrimSpace(request.Password) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "email_and_password_required"})
		return
	}
	if neonPath == "/sign-up/email" && strings.TrimSpace(request.Name) == "" {
		request.Name = memberDefaultUserName(request.Email)
	}

	result, configured := h.callMemberNeonEmailAuth(r, request, neonPath)
	if !configured {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "neon_auth_not_configured", "message": "Authentication is temporarily unavailable."})
		return
	}
	if result.StatusCode/100 != 2 {
		writeMemberAuthProviderError(w, result)
		return
	}

	jwt := result.Token
	endpoint := memberNeonEndpointName(neonPath)
	if jwt == "" && neonPath == "/sign-up/email" {
		fallback, fallbackConfigured := h.callMemberNeonEmailAuth(r, memberEmailAuthRequest{Email: request.Email, Password: request.Password, CallbackURL: request.CallbackURL}, "/sign-in/email")
		if !fallbackConfigured {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "neon_auth_not_configured", "message": "Authentication is temporarily unavailable."})
			return
		}
		if fallback.StatusCode/100 != 2 {
			writeJSON(w, http.StatusBadGateway, map[string]string{"error": "auth_session_missing", "message": "Account was created, but no session token was returned. Please sign in."})
			return
		}
		jwt = fallback.Token
		result = fallback
		endpoint = "signup_fallback_login"
	}
	if jwt == "" {
		writeJSON(w, http.StatusBadGateway, map[string]string{"error": "auth_session_missing", "message": "The authentication provider did not return a session. Please try again."})
		return
	}

	claims, err := parseAndVerifyNeonJWT(jwt)
	safeAuthDebugLog(endpoint+"_verify", result.StatusCode, result.Body, nil, result.TokenFound, err == nil)
	if err != nil {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_token", "message": "The authentication response could not be verified."})
		return
	}
	profile, err := h.memberAuthSuccessProfile(r, claims)
	if errors.Is(err, errAccountDisabled) {
		writeJSON(w, http.StatusForbidden, map[string]string{"error": "account_disabled", "message": "Account access is disabled."})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "profile_provision_failed", "message": "The authenticated account could not be provisioned."})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "token": jwt, "access_token": jwt, "token_type": "Bearer", "user": profile})
}

func (h *Handler) callMemberNeonEmailAuth(r *http.Request, request memberEmailAuthRequest, neonPath string) (memberNeonAuthResult, bool) {
	baseURL := strings.TrimRight(strings.TrimSpace(configuredNeonAuthBaseURL()), "/")
	if baseURL == "" {
		return memberNeonAuthResult{}, false
	}
	payload := map[string]string{"email": strings.ToLower(strings.TrimSpace(request.Email)), "password": request.Password, "callbackURL": memberAbsoluteAuthCallbackURL(r, request.CallbackURL)}
	if name := strings.TrimSpace(request.Name); name != "" {
		payload["name"] = name
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return memberNeonAuthResult{StatusCode: http.StatusInternalServerError, Data: map[string]any{"error": "auth_request_failed"}}, true
	}

	origin := publicBaseURL(r)
	requestToNeon, err := http.NewRequestWithContext(r.Context(), http.MethodPost, baseURL+neonPath, bytes.NewReader(body))
	if err != nil {
		return memberNeonAuthResult{StatusCode: http.StatusInternalServerError, Data: map[string]any{"error": "auth_request_failed"}}, true
	}
	requestToNeon.Header.Set("Content-Type", "application/json")
	requestToNeon.Header.Set("Accept", "application/json")
	if origin != "" {
		requestToNeon.Header.Set("Origin", origin)
	}

	client := &http.Client{Timeout: 10 * time.Second}
	response, err := client.Do(requestToNeon)
	if err != nil {
		return memberNeonAuthResult{StatusCode: http.StatusBadGateway, Data: map[string]any{"error": "neon_auth_unavailable", "message": "The authentication provider is temporarily unreachable."}}, true
	}
	defer response.Body.Close()
	responseBody, _ := io.ReadAll(io.LimitReader(response.Body, 1<<20))
	data := map[string]any{}
	if len(responseBody) > 0 {
		_ = json.Unmarshal(responseBody, &data)
	}
	if len(data) == 0 && response.StatusCode/100 != 2 {
		data = map[string]any{"error": "auth_provider_failed", "message": http.StatusText(response.StatusCode)}
	}
	jwt, tokenFound := extractAuthToken(response, responseBody)
	cookies := response.Cookies()
	safeAuthDebugLog(memberNeonEndpointName(neonPath), response.StatusCode, responseBody, cookies, tokenFound, false)
	if !tokenFound && response.StatusCode/100 == 2 && len(cookies) > 0 {
		if exchanged, ok := exchangeMemberNeonSessionToken(r.Context(), client, baseURL, origin, cookies); ok {
			jwt = exchanged
			tokenFound = true
		}
	}
	return memberNeonAuthResult{StatusCode: response.StatusCode, Data: data, Body: responseBody, Token: jwt, TokenFound: tokenFound}, true
}

func exchangeMemberNeonSessionToken(ctx context.Context, client *http.Client, baseURL, origin string, cookies []*http.Cookie) (string, bool) {
	attempts := []struct {
		method string
		path   string
	}{
		{http.MethodGet, "/token"},
		{http.MethodGet, "/get-session"},
		{http.MethodPost, "/token"},
		{http.MethodPost, "/get-session"},
	}
	for _, attempt := range attempts {
		var body io.Reader
		if attempt.method == http.MethodPost {
			body = strings.NewReader("{}")
		}
		req, err := http.NewRequestWithContext(ctx, attempt.method, baseURL+attempt.path, body)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/json")
		if attempt.method == http.MethodPost {
			req.Header.Set("Content-Type", "application/json")
		}
		if origin != "" {
			req.Header.Set("Origin", origin)
		}
		for _, cookie := range cookies {
			if cookie != nil {
				req.AddCookie(cookie)
			}
		}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		responseBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
		_ = resp.Body.Close()
		token, found := extractAuthToken(resp, responseBody)
		safeAuthDebugLog("session_exchange_"+strings.Trim(strings.ReplaceAll(attempt.path, "/", "_"), "_"), resp.StatusCode, responseBody, resp.Cookies(), found, false)
		if resp.StatusCode/100 == 2 && found {
			return token, true
		}
	}
	return "", false
}

func writeMemberAuthProviderError(w http.ResponseWriter, result memberNeonAuthResult) {
	status := result.StatusCode
	if status < http.StatusBadRequest || status > 599 {
		status = http.StatusBadGateway
	}
	if len(result.Data) == 0 {
		writeJSON(w, status, map[string]string{"error": "auth_provider_failed", "message": "Authentication failed."})
		return
	}
	writeJSON(w, status, result.Data)
}

func memberDefaultUserName(email string) string {
	name := strings.TrimSpace(strings.Split(email, "@")[0])
	if name == "" {
		return "User"
	}
	return name
}

func memberNeonEndpointName(neonPath string) string {
	switch neonPath {
	case "/sign-up/email":
		return "signup"
	case "/sign-in/email":
		return "login"
	default:
		return strings.Trim(strings.ReplaceAll(neonPath, "/", "_"), "_")
	}
}

func memberAbsoluteAuthCallbackURL(r *http.Request, requested string) string {
	fallback := absolutePublicURL(r, "/dashboard")
	requested = strings.TrimSpace(requested)
	if requested == "" || strings.ContainsAny(requested, "\r\n") {
		return fallback
	}
	if parsed, err := url.Parse(requested); err == nil && parsed.IsAbs() && parsed.Host != "" && (parsed.Scheme == "http" || parsed.Scheme == "https") {
		publicURL, publicErr := url.Parse(publicBaseURL(r))
		if publicErr == nil && publicURL.Host != "" && strings.EqualFold(parsed.Host, publicURL.Host) {
			return strings.TrimRight(parsed.String(), "/")
		}
		return fallback
	}
	if strings.HasPrefix(requested, "/") && !strings.HasPrefix(requested, "//") {
		return absolutePublicURL(r, requested)
	}
	return fallback
}

func (h *Handler) memberAuthSuccessProfile(r *http.Request, claims neonJWTClaims) (map[string]any, error) {
	profile := map[string]any{"auth_subject": claims.Sub, "email": claims.Email, "role": "member", "plan_id": "free", "plan": "free", "credits": 0, "outputs_total": 0, "outputs_remaining": 0}
	if h.DB == nil {
		return profile, nil
	}
	if err := ensureOwnerSchema(r.Context(), h.DB); err != nil {
		return nil, err
	}
	summary, err := h.provisionMember(r.Context(), claims)
	if err != nil {
		return nil, err
	}
	stored, err := h.upsertProfile(r.Context(), claims.Sub, claims.Email)
	if err != nil {
		return nil, err
	}
	return map[string]any{"id": stored.ID, "auth_subject": stored.AuthSubject, "email": stored.Email, "role": firstNonEmpty(stored.Role, "member"), "plan_id": firstNonEmpty(summary.Plan, stored.PlanID, "free"), "plan": firstNonEmpty(summary.Plan, stored.PlanID, "free"), "credits": stored.Credits, "outputs_total": summary.OutputsTotal, "outputs_remaining": summary.OutputsRemaining}, nil
}
