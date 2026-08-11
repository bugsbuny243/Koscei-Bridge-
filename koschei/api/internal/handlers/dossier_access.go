package handlers

import (
	"context"
	"database/sql"
	"math/big"
	"net/http"
	"strings"
	"time"
)

type storedTokenAccessEvaluator func(context.Context, string) (tokenAccessEvaluation, error)

// evaluateStoredTokenAccess reads the latest unexpired entitlement snapshot. It
// deliberately performs no Solana RPC call; dossier export is a stored-evidence
// operation and cannot refresh wallet balances or scan data.
func (h *Handler) evaluateStoredTokenAccess(ctx context.Context, authSubject string) (tokenAccessEvaluation, error) {
	if h == nil || h.DB == nil {
		return tokenAccessEvaluation{}, sql.ErrConnDone
	}
	var out tokenAccessEvaluation
	var amountRaw string
	var checkedAt, expiresAt time.Time
	err := h.DB.QueryRowContext(ctx, `
		SELECT wallet_address,network,mint_address,amount_raw::text,decimals,tier,gate_enabled,checked_at,expires_at
		FROM token_access_snapshots
		WHERE auth_subject=$1 AND expires_at>now()
		ORDER BY checked_at DESC
		LIMIT 1`, strings.TrimSpace(authSubject)).Scan(
		&out.WalletAddress, &out.Network, &out.MintAddress, &amountRaw, &out.Decimals,
		&out.Tier, &out.GateEnabled, &checkedAt, &expiresAt,
	)
	if err != nil {
		return tokenAccessEvaluation{}, err
	}
	out.WalletAddress = strings.TrimSpace(out.WalletAddress)
	out.Network = strings.TrimSpace(out.Network)
	out.MintAddress = strings.TrimSpace(out.MintAddress)
	out.AmountRaw = strings.TrimSpace(amountRaw)
	out.Configured = out.MintAddress != ""
	out.WalletVerified = out.WalletAddress != ""
	out.CheckedAt = timePointer(checkedAt.UTC())
	out.SnapshotExpires = timePointer(expiresAt.UTC())
	if raw, ok := new(big.Int).SetString(out.AmountRaw, 10); ok && raw.Sign() >= 0 {
		out.Amount = formatTokenAmount(raw, out.Decimals)
	}
	return out, nil
}

func timePointer(value time.Time) *time.Time { return &value }

func (h *Handler) RequireStoredTokenTier(required string, next http.HandlerFunc) http.HandlerFunc {
	return h.requireStoredTokenTierWithEvaluator(required, h.evaluateStoredTokenAccess, next)
}

func (h *Handler) requireStoredTokenTierWithEvaluator(required string, evaluate storedTokenAccessEvaluator, next http.HandlerFunc) http.HandlerFunc {
	required = strings.ToLower(strings.TrimSpace(required))
	return func(w http.ResponseWriter, r *http.Request) {
		claims, ok := userFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if tokenTierRank(required) == 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "invalid_required_token_tier"})
			return
		}
		evaluation, err := evaluate(r.Context(), claims.Sub)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "token_access_snapshot_required", "required_tier": required})
			return
		}
		if !evaluation.GateEnabled || !evaluation.Configured || !evaluation.WalletVerified || tokenTierRank(evaluation.Tier) < tokenTierRank(required) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "token_tier_required", "required_tier": required, "current_tier": evaluation.Tier})
			return
		}
		ctx := withTokenAccessRequestContext(r.Context(), tokenAccessRequestContext{
			Evaluation: evaluation, AuthSubject: claims.Sub, Email: claims.Email,
		})
		next(w, r.WithContext(ctx))
	}
}

func (h *Handler) RequireAPIKeyStoredTokenTier(required string, next http.HandlerFunc) http.HandlerFunc {
	required = strings.ToLower(strings.TrimSpace(required))
	return func(w http.ResponseWriter, r *http.Request) {
		principal, ok := apiPrincipalFromContext(r.Context())
		if !ok {
			writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
			return
		}
		if tokenTierRank(required) == 0 {
			writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "invalid_required_token_tier"})
			return
		}
		evaluation, err := h.evaluateStoredTokenAccess(r.Context(), principal.AuthSubject)
		if err != nil {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "token_access_snapshot_required", "required_tier": required})
			return
		}
		if !evaluation.GateEnabled || !evaluation.Configured || !evaluation.WalletVerified || tokenTierRank(evaluation.Tier) < tokenTierRank(required) {
			writeJSON(w, http.StatusForbidden, map[string]any{"error": "token_tier_required", "required_tier": required, "current_tier": evaluation.Tier})
			return
		}
		ctx := withTokenAccessRequestContext(r.Context(), tokenAccessRequestContext{
			Evaluation: evaluation, AuthSubject: principal.AuthSubject, Email: principal.Email,
		})
		next(w, r.WithContext(ctx))
	}
}

// DossierAccess accepts owner credentials, enterprise API keys or an enterprise
// user session. The selected path is explicit so one credential type never falls
// through into another authentication mechanism. The resulting export remains
// private by default even when the canonical bundle itself is durable.
func (h *Handler) DossierAccess(next http.HandlerFunc) http.HandlerFunc {
	next = privateDossierExport(next)
	return func(w http.ResponseWriter, r *http.Request) {
		if dossierOwnerCredentialPresent(r) {
			if !h.OwnerAuth(w, r) {
				return
			}
			next(w, r)
			return
		}
		apiKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
		bearer := bearerToken(r.Header.Get("Authorization"))
		if apiKey != "" || strings.HasPrefix(bearer, "kch_live_") {
			h.APIKeyAuth(h.RequireAPIKeyStoredTokenTier("enterprise", next))(w, r)
			return
		}
		RequireAuth(h.RequireStoredTokenTier("enterprise", next))(w, r)
	}
}

func dossierOwnerCredentialPresent(r *http.Request) bool {
	for _, name := range []string{"x-koschei-secret", "x-owner-secret", "x-admin-password"} {
		if strings.TrimSpace(r.Header.Get(name)) != "" {
			return true
		}
	}
	if cookie, err := r.Cookie("koschei_owner_secret"); err == nil && strings.TrimSpace(cookie.Value) != "" {
		return true
	}
	return false
}
