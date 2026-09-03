package handlers

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	ownerSessionCookieName = "koschei_owner_session"
	ownerSessionTTL        = 12 * time.Hour
	ownerSessionTokenBytes = 32
	ownerSessionMemoryMax  = 64
)

type ownerSessionRecord struct {
	Wallet    string
	ExpiresAt time.Time
}

var ownerSessionMemory = struct {
	sync.Mutex
	items map[string]ownerSessionRecord
}{items: map[string]ownerSessionRecord{}}

func (h *Handler) issueOwnerSession(ctx context.Context, wallet string, r *http.Request) (string, time.Time, error) {
	token, err := randomOwnerSessionToken()
	if err != nil {
		return "", time.Time{}, err
	}
	now := time.Now().UTC()
	expiresAt := now.Add(ownerSessionTTL)
	hash := ownerSessionHash(token)
	wallet = normalizeWallet(wallet)

	if h != nil && h.DB != nil {
		_, _ = h.DB.ExecContext(ctx, `DELETE FROM owner_sessions WHERE expires_at <= now() OR revoked_at IS NOT NULL`)
		_, err = h.DB.ExecContext(ctx, `INSERT INTO owner_sessions
			(session_hash,wallet_address,user_agent_hash,ip_hash,created_at,expires_at,last_seen_at)
			VALUES ($1,NULLIF($2,''),NULLIF($3,''),NULLIF($4,''),$5,$6,$5)`,
			hash, wallet, ownerSessionAuditHash(requestUserAgent(r)), ownerSessionAuditHash(requestAuditIP(r)), now, expiresAt)
		if err != nil {
			return "", time.Time{}, err
		}
		return token, expiresAt, nil
	}
	if isProduction() {
		return "", time.Time{}, errors.New("owner session database unavailable")
	}

	ownerSessionMemory.Lock()
	defer ownerSessionMemory.Unlock()
	cleanupOwnerSessionMemoryLocked(now)
	if len(ownerSessionMemory.items) >= ownerSessionMemoryMax {
		revokeOldestOwnerSessionLocked()
	}
	ownerSessionMemory.items[hash] = ownerSessionRecord{Wallet: wallet, ExpiresAt: expiresAt}
	return token, expiresAt, nil
}

func (h *Handler) ownerSessionFromRequest(ctx context.Context, r *http.Request) (string, bool) {
	if r == nil {
		return "", false
	}
	cookie, err := r.Cookie(ownerSessionCookieName)
	if err != nil {
		return "", false
	}
	token := strings.TrimSpace(cookie.Value)
	if token == "" {
		return "", false
	}
	hash := ownerSessionHash(token)

	if h != nil && h.DB != nil {
		var wallet string
		var expiresAt time.Time
		err = h.DB.QueryRowContext(ctx, `UPDATE owner_sessions
			SET last_seen_at=now()
			WHERE session_hash=$1 AND revoked_at IS NULL AND expires_at > now()
			RETURNING COALESCE(wallet_address,''), expires_at`, hash).Scan(&wallet, &expiresAt)
		if err != nil || !expiresAt.After(time.Now().UTC()) {
			return "", false
		}
		return normalizeWallet(wallet), true
	}
	if isProduction() {
		return "", false
	}

	now := time.Now().UTC()
	ownerSessionMemory.Lock()
	defer ownerSessionMemory.Unlock()
	cleanupOwnerSessionMemoryLocked(now)
	record, ok := ownerSessionMemory.items[hash]
	if !ok || !record.ExpiresAt.After(now) {
		return "", false
	}
	return normalizeWallet(record.Wallet), true
}

func (h *Handler) revokeOwnerSession(ctx context.Context, r *http.Request) {
	if r == nil {
		return
	}
	cookie, err := r.Cookie(ownerSessionCookieName)
	if err != nil || strings.TrimSpace(cookie.Value) == "" {
		return
	}
	hash := ownerSessionHash(cookie.Value)
	if h != nil && h.DB != nil {
		_, _ = h.DB.ExecContext(ctx, `UPDATE owner_sessions SET revoked_at=COALESCE(revoked_at,now()) WHERE session_hash=$1`, hash)
		return
	}
	ownerSessionMemory.Lock()
	delete(ownerSessionMemory.items, hash)
	ownerSessionMemory.Unlock()
}

func setOwnerSessionCookies(w http.ResponseWriter, token, wallet string, expiresAt time.Time) {
	secure := isProduction()
	maxAge := int(time.Until(expiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 1
	}
	http.SetCookie(w, &http.Cookie{
		Name:     ownerSessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		Expires:  expiresAt,
		MaxAge:   maxAge,
	})
	if wallet = normalizeWallet(wallet); wallet != "" {
		http.SetCookie(w, &http.Cookie{
			Name:     "koschei_owner_wallet",
			Value:    wallet,
			Path:     "/",
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
			Expires:  expiresAt,
			MaxAge:   maxAge,
		})
	}
	clearOwnerCookie(w, "koschei_owner_secret")
}

func clearOwnerSessionCookies(w http.ResponseWriter) {
	for _, name := range []string{ownerSessionCookieName, "koschei_owner_secret", "koschei_owner_wallet"} {
		clearOwnerCookie(w, name)
	}
}

func clearOwnerCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		Secure:   isProduction(),
		SameSite: http.SameSiteStrictMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
}

func randomOwnerSessionToken() (string, error) {
	buffer := make([]byte, ownerSessionTokenBytes)
	if _, err := rand.Read(buffer); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buffer), nil
}

func ownerSessionHash(token string) string {
	digest := sha256.Sum256([]byte(strings.TrimSpace(token)))
	return "sha256:" + hex.EncodeToString(digest[:])
}

func ownerSessionAuditHash(value string) string {
	value = strings.TrimSpace(value)
	if value == "" || value == "unknown" {
		return ""
	}
	return ownerSessionHash(value)
}

func requestUserAgent(r *http.Request) string {
	if r == nil {
		return ""
	}
	value := strings.TrimSpace(r.UserAgent())
	if len(value) > 512 {
		value = value[:512]
	}
	return value
}

func cleanupOwnerSessionMemoryLocked(now time.Time) {
	for hash, record := range ownerSessionMemory.items {
		if !record.ExpiresAt.After(now) {
			delete(ownerSessionMemory.items, hash)
		}
	}
}

func revokeOldestOwnerSessionLocked() {
	oldestHash := ""
	var oldestExpiry time.Time
	for hash, record := range ownerSessionMemory.items {
		if oldestHash == "" || record.ExpiresAt.Before(oldestExpiry) {
			oldestHash = hash
			oldestExpiry = record.ExpiresAt
		}
	}
	if oldestHash != "" {
		delete(ownerSessionMemory.items, oldestHash)
	}
}
