package handlers

import (
	"crypto/sha256"
	"crypto/subtle"
	"net/http"
	"strings"

	"koschei/api/pkg/utils"
)

func (h *Handler) ownerAuth(w http.ResponseWriter, r *http.Request) bool {
	if neonAuthOnlyMode() {
		if _, ok := verifiedOwnerNeonClaims(r); !ok {
			http.NotFound(w, r)
			return false
		}
		return true
	}

	ownerWallet := normalizeWallet(firstEnv("OWNER_WALLET", "KOSCHEI_OWNER_WALLET"))
	ownerSecret := strings.TrimSpace(firstEnv("OWNER_SECRET", "KOSCHEI_OWNER_SECRET"))
	if ownerSecret == "" {
		http.NotFound(w, r)
		return false
	}

	sessionWallet, sessionOK := h.ownerSessionFromRequest(r.Context(), r)
	credentialOK := sessionOK
	if !credentialOK {
		suppliedSecret := strings.TrimSpace(r.Header.Get("x-koschei-secret"))
		if suppliedSecret == "" {
			suppliedSecret = strings.TrimSpace(r.Header.Get("x-owner-secret"))
		}
		if suppliedSecret == "" {
			suppliedSecret = strings.TrimSpace(r.Header.Get("x-admin-password"))
		}
		credentialOK = suppliedSecret != "" && constantTimeStringEqual(suppliedSecret, ownerSecret)
	}
	if !credentialOK {
		http.NotFound(w, r)
		return false
	}

	wallet := sessionWallet
	if !sessionOK {
		wallet = normalizeWallet(r.Header.Get("x-owner-wallet"))
		if wallet == "" {
			if c, err := r.Cookie("koschei_owner_wallet"); err == nil {
				wallet = normalizeWallet(c.Value)
			}
		}
		if wallet == "" {
			wallet = walletFromBearer(r)
		}
	}
	if ownerWallet != "" && wallet != "" && wallet != ownerWallet {
		http.NotFound(w, r)
		return false
	}
	return true
}

func (h *Handler) OwnerAuth(w http.ResponseWriter, r *http.Request) bool {
	return h.ownerAuth(w, r)
}

func verifiedOwnerNeonClaims(r *http.Request) (neonJWTClaims, bool) {
	var zero neonJWTClaims
	if r == nil {
		return zero, false
	}
	ownerEmail := strings.ToLower(strings.TrimSpace(firstEnv("OWNER_EMAIL", "KOSCHEI_OWNER_EMAIL")))
	if ownerEmail == "" {
		return zero, false
	}
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return zero, false
	}
	claims, err := parseAndVerifyNeonJWT(strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer ")))
	if err != nil {
		return zero, false
	}
	if !constantTimeStringEqual(strings.ToLower(strings.TrimSpace(claims.Email)), ownerEmail) {
		return zero, false
	}
	if strings.TrimSpace(claims.Sub) == "" {
		return zero, false
	}
	return claims, true
}

func walletFromBearer(r *http.Request) string {
	authHeader := strings.TrimSpace(r.Header.Get("Authorization"))
	if !strings.HasPrefix(authHeader, "Bearer ") {
		return ""
	}
	token := strings.TrimSpace(strings.TrimPrefix(authHeader, "Bearer "))
	claims, err := parseAndVerifyNeonJWT(token)
	if err != nil {
		return ""
	}
	if wallet, err := utils.GetWalletFromJWT(token); err == nil {
		return normalizeWallet(wallet)
	}
	for _, candidate := range []string{claims.Wallet, claims.WalletAddress, claims.PublicAddress} {
		if wallet := normalizeWallet(candidate); wallet != "" {
			return wallet
		}
	}
	return ""
}

func normalizeWallet(v string) string {
	return strings.ToLower(strings.TrimSpace(v))
}

func constantTimeStringEqual(a, b string) bool {
	aHash := sha256.Sum256([]byte(a))
	bHash := sha256.Sum256([]byte(b))
	return subtle.ConstantTimeCompare(aHash[:], bHash[:]) == 1
}
