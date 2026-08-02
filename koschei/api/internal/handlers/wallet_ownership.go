package handlers

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const solanaBase58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

type walletChallengeRequest struct {
	WalletAddress string `json:"wallet_address"`
	Network       string `json:"network"`
}

type walletVerifyRequest struct {
	ChallengeID string `json:"challenge_id"`
	Signature   string `json:"signature"`
}

func (h *Handler) CreateWalletChallenge(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if h.Limiter != nil && !h.Limiter.allow("wallet-challenge:"+claims.Sub, 10, 10*time.Minute) {
		writeJSON(w, http.StatusTooManyRequests, map[string]string{"error": "rate_limit_exceeded"})
		return
	}
	var req walletChallengeRequest
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	wallet := strings.TrimSpace(req.WalletAddress)
	if _, err := decodeSolanaPublicKey(wallet); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_wallet_address"})
		return
	}
	network, ok := normalizeWalletNetwork(req.Network)
	if !ok {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "unsupported_network"})
		return
	}

	nonceBytes := make([]byte, 32)
	if _, err := rand.Read(nonceBytes); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "challenge_generation_failed"})
		return
	}
	nonce := base64.RawURLEncoding.EncodeToString(nonceBytes)
	nonceSum := sha256.Sum256([]byte(nonce))
	nonceHash := hex.EncodeToString(nonceSum[:])
	issuedAt := time.Now().UTC()
	expiresAt := issuedAt.Add(5 * time.Minute)
	message := fmt.Sprintf("Koschei wallet verification\nDomain: tradepigloball.co\nWallet: %s\nNetwork: %s\nNonce: %s\nIssued At: %s\nExpiration Time: %s\nStatement: Sign this message to link your wallet. This does not authorize a transaction.", wallet, network, nonce, issuedAt.Format(time.RFC3339), expiresAt.Format(time.RFC3339))

	var challengeID string
	if err := h.DB.QueryRowContext(r.Context(), `
		INSERT INTO wallet_signing_challenges (auth_subject,wallet_address,network,nonce_hash,message,expires_at)
		VALUES ($1,$2,$3,$4,$5,$6)
		RETURNING id::text`, claims.Sub, wallet, network, nonceHash, message, expiresAt).Scan(&challengeID); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "challenge_store_failed"})
		return
	}
	services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "wallet_challenge_created", "customer", "info", map[string]any{"wallet_address": wallet, "network": network, "challenge_id": challengeID}))
	writeJSON(w, http.StatusCreated, map[string]any{
		"challenge_id":   challengeID,
		"wallet_address": wallet,
		"network":        network,
		"message":        message,
		"expires_at":     expiresAt,
	})
}

func (h *Handler) VerifyWalletChallenge(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var req walletVerifyRequest
	if err := decodeJSON(r, &req); err != nil || strings.TrimSpace(req.ChallengeID) == "" || strings.TrimSpace(req.Signature) == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	defer tx.Rollback()

	var wallet, network, message string
	err = tx.QueryRowContext(r.Context(), `
		SELECT wallet_address,network,message
		FROM wallet_signing_challenges
		WHERE id=$1 AND auth_subject=$2 AND used_at IS NULL AND expires_at>now()
		FOR UPDATE`, strings.TrimSpace(req.ChallengeID), claims.Sub).Scan(&wallet, &network, &message)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusGone, map[string]string{"error": "challenge_expired_or_used"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}

	publicKey, err := decodeSolanaPublicKey(wallet)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_wallet_address"})
		return
	}
	signature, err := decodeWalletSignature(req.Signature)
	if err != nil || !ed25519.Verify(ed25519.PublicKey(publicKey), []byte(message), signature) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "invalid_wallet_signature"})
		return
	}

	var otherSubject string
	err = tx.QueryRowContext(r.Context(), `SELECT auth_subject FROM verified_wallet_links WHERE network=$1 AND wallet_address=$2 AND status='active' AND auth_subject<>$3 LIMIT 1`, network, wallet, claims.Sub).Scan(&otherSubject)
	if err == nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "wallet_already_linked"})
		return
	}
	if err != nil && err != sql.ErrNoRows {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}

	_, _ = tx.ExecContext(r.Context(), `DELETE FROM verified_wallet_links WHERE network=$1 AND wallet_address=$2 AND status='revoked' AND auth_subject<>$3`, network, wallet, claims.Sub)
	_, err = tx.ExecContext(r.Context(), `
		INSERT INTO verified_wallet_links (auth_subject,wallet_address,network,status,verified_at)
		VALUES ($1,$2,$3,'active',now())
		ON CONFLICT (auth_subject,network) DO UPDATE SET
			wallet_address=EXCLUDED.wallet_address,
			status='active',
			verified_at=now(),
			revoked_at=NULL,
			updated_at=now()`, claims.Sub, wallet, network)
	if err != nil {
		writeJSON(w, http.StatusConflict, map[string]string{"error": "wallet_link_conflict"})
		return
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE wallet_signing_challenges SET used_at=now() WHERE id=$1 AND used_at IS NULL`, strings.TrimSpace(req.ChallengeID)); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE app_user_profiles SET wallet_address=$1,updated_at=now() WHERE auth_subject=$2 AND status='active'`, wallet, claims.Sub); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "profile_update_failed"})
		return
	}
	if err = tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "wallet_link_verified", "customer", "info", map[string]any{"wallet_address": wallet, "network": network}))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "wallet_address": wallet, "network": network, "verified": true})
}

func (h *Handler) WalletLinkStatus(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	var wallet, network string
	var verifiedAt time.Time
	err := h.DB.QueryRowContext(r.Context(), `SELECT wallet_address,network,verified_at FROM verified_wallet_links WHERE auth_subject=$1 AND status='active' ORDER BY verified_at DESC LIMIT 1`, claims.Sub).Scan(&wallet, &network, &verifiedAt)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "linked": false})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "linked": true, "wallet_address": wallet, "network": network, "verified_at": verifiedAt})
}

func (h *Handler) UnlinkWallet(w http.ResponseWriter, r *http.Request) {
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	defer tx.Rollback()
	var wallet string
	err = tx.QueryRowContext(r.Context(), `UPDATE verified_wallet_links SET status='revoked',revoked_at=now(),updated_at=now() WHERE auth_subject=$1 AND status='active' RETURNING wallet_address`, claims.Sub).Scan(&wallet)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "wallet_not_linked"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	if _, err = tx.ExecContext(r.Context(), `UPDATE app_user_profiles SET wallet_address=NULL,updated_at=now() WHERE auth_subject=$1 AND wallet_address=$2`, claims.Sub, wallet); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "profile_update_failed"})
		return
	}
	if err = tx.Commit(); err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "db_failed"})
		return
	}
	services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "wallet_link_revoked", "customer", "warning", map[string]any{"wallet_address": wallet}))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "unlinked": true})
}

func normalizeWalletNetwork(value string) (string, bool) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "mainnet", "mainnet-beta", "solana-mainnet":
		return "solana-mainnet", true
	case "devnet", "solana-devnet":
		return "solana-devnet", true
	default:
		return "", false
	}
}

func decodeSolanaPublicKey(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	if len(value) < 32 || len(value) > 44 {
		return nil, errors.New("invalid public key length")
	}
	return decodeBase58Exact(value, ed25519.PublicKeySize)
}

func decodeWalletSignature(value string) ([]byte, error) {
	value = strings.TrimSpace(value)
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		decoded, err := encoding.DecodeString(value)
		if err == nil && len(decoded) == ed25519.SignatureSize {
			return decoded, nil
		}
	}
	return decodeBase58Exact(value, ed25519.SignatureSize)
}

func decodeBase58Exact(value string, expected int) ([]byte, error) {
	if value == "" {
		return nil, errors.New("empty base58 value")
	}
	result := big.NewInt(0)
	base := big.NewInt(58)
	for _, char := range value {
		index := strings.IndexRune(solanaBase58Alphabet, char)
		if index < 0 {
			return nil, errors.New("invalid base58 character")
		}
		result.Mul(result, base)
		result.Add(result, big.NewInt(int64(index)))
	}
	decoded := result.Bytes()
	leadingZeros := 0
	for leadingZeros < len(value) && value[leadingZeros] == '1' {
		leadingZeros++
	}
	if leadingZeros+len(decoded) > expected {
		return nil, errors.New("decoded value is too large")
	}
	out := make([]byte, expected)
	copy(out[expected-len(decoded):], decoded)
	return out, nil
}
