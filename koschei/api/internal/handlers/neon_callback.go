package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
)

// NeonCallback handles the redirect back from Neon Auth and forwards Neon JWTs to the frontend URL hash.
func (h *Handler) NeonCallback(w http.ResponseWriter, r *http.Request) {
	redirectTo := "/hub.html"
	if state := r.URL.Query().Get("state"); state != "" {
		if parsedRedirect, ok := h.parseNeonAuthState(state); ok {
			redirectTo = parsedRedirect
		} else {
			http.Redirect(w, r, "/login.html?error=invalid_state", http.StatusTemporaryRedirect)
			return
		}
	}

	token := firstQueryValue(r, "access_token", "token", "id_token")
	serveNeonCallbackBridge(w, redirectTo, token)
}

func serveNeonCallbackBridge(w http.ResponseWriter, redirectTo, callbackToken string) {
	redirectJSON, _ := json.Marshal(redirectTo)
	tokenJSON, _ := json.Marshal(callbackToken)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	_, _ = fmt.Fprintf(w, `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Completing Neon Auth — Koschei</title></head>
<body><p>Completing Neon Auth…</p><script>
(function(){
  var redirectTo = %s;
	var callbackToken = %s;
  var params = new URLSearchParams((window.location.hash || '').replace(/^#/, ''));
	var token = callbackToken || params.get('access_token') || params.get('token') || params.get('id_token') || '';
  if (token) {
    window.location.replace(redirectTo + (redirectTo.indexOf('#') === -1 ? '#' : '&') + 'access_token=' + encodeURIComponent(token));
    return;
  }
  window.location.replace(redirectTo);
})();
</script></body>
</html>`, string(redirectJSON), string(tokenJSON))
}

func firstQueryValue(r *http.Request, keys ...string) string {
	for _, key := range keys {
		if value := r.URL.Query().Get(key); value != "" {
			return value
		}
	}
	return ""
}

// This file intentionally passes through only Neon-issued tokens; API middleware keeps JWT verification in neon_auth.go/jwt_verify.go.
