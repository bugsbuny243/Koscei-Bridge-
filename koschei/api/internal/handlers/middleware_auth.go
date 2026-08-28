package handlers

import (
	"context"
	"log"
	"net/http"
	"strings"
)

type contextKey string

const authContextKey contextKey = "auth_claims"

func RequireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(h, "Bearer ") {
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		claims, err := parseAndVerifyNeonJWT(strings.TrimSpace(strings.TrimPrefix(h, "Bearer ")))
		if err != nil {
			log.Printf("neon auth verify failed: %v", err)
			writeJSON(w, 401, map[string]string{"error": "unauthorized"})
			return
		}
		r = r.WithContext(context.WithValue(r.Context(), authContextKey, claims))
		next(w, r)
	}
}

func userFromContext(ctx context.Context) (neonJWTClaims, bool) {
	v := ctx.Value(authContextKey)
	claims, ok := v.(neonJWTClaims)
	return claims, ok
}

// AuthenticatedSubject returns the already-verified customer subject installed by RequireAuth.
// It intentionally exposes only the stable subject needed by downstream shared security middleware.
func AuthenticatedSubject(r *http.Request) string {
	if r == nil {
		return ""
	}
	claims, ok := userFromContext(r.Context())
	if !ok {
		return ""
	}
	return strings.TrimSpace(claims.Sub)
}
