package handlers

import (
	"database/sql"
	"net/http"
	"strings"
	"time"
)

// OwnerKOSCHAccessV2 returns the current wallet verification and latest KOSCH
// snapshot without depending on legacy package or credit data. Token holdings
// expose access/capacity capabilities only; they never expose evidence, verdict,
// compiler, model-promotion or integration authority.
func (h *Handler) OwnerKOSCHAccessV2(w http.ResponseWriter, r *http.Request) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil || !ownerTableExists(r.Context(), db, "app_user_profiles") {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "users": []any{}, "summary": map[string]any{}})
		return
	}

	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	walletJoin := `LEFT JOIN LATERAL (
		SELECT wallet_address, verified_at
		FROM verified_wallet_links v
		WHERE v.auth_subject=p.auth_subject AND v.status='active'
		ORDER BY verified_at DESC LIMIT 1
	) vw ON true`
	if !ownerTableExists(r.Context(), db, "verified_wallet_links") {
		walletJoin = `LEFT JOIN LATERAL (
			SELECT NULL::text wallet_address, NULL::timestamptz verified_at
		) vw ON true`
	}

	snapshotJoin := `LEFT JOIN LATERAL (
		SELECT tier,
		       (amount_raw / power(10::numeric, decimals))::text AS amount,
		       amount_raw::text AS amount_raw,
		       checked_at,
		       expires_at
		FROM token_access_snapshots s
		WHERE s.auth_subject=p.auth_subject
		ORDER BY checked_at DESC LIMIT 1
	) ts ON true`
	if !ownerTableExists(r.Context(), db, "token_access_snapshots") {
		snapshotJoin = `LEFT JOIN LATERAL (
			SELECT NULL::text tier, NULL::text amount, NULL::text amount_raw,
			       NULL::timestamptz checked_at, NULL::timestamptz expires_at
		) ts ON true`
	}

	rows, err := db.QueryContext(r.Context(), `
		SELECT p.id::text,
		       COALESCE(p.auth_subject,''),
		       lower(p.email),
		       COALESCE(NULLIF(vw.wallet_address,''),NULLIF(p.wallet_address,''),''),
		       COALESCE(p.status,'active'),
		       p.created_at,
		       vw.verified_at,
		       COALESCE(ts.tier,'none'),
		       COALESCE(ts.amount,'0'),
		       ts.checked_at,
		       ts.expires_at
		FROM app_user_profiles p
		`+walletJoin+`
		`+snapshotJoin+`
		WHERE ($1='' OR lower(p.email) LIKE $2
		       OR lower(COALESCE(p.auth_subject,'')) LIKE $2
		       OR lower(COALESCE(vw.wallet_address,p.wallet_address,'')) LIKE $2)
		ORDER BY p.created_at DESC
		LIMIT 500`, q, "%"+q+"%")
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]any{"ok": false, "error": "kosch_access_query_failed"})
		return
	}
	defer rows.Close()

	users := []map[string]any{}
	counts := map[string]int64{"total": 0, "verified": 0, "holders": 0, "basic": 0, "pro": 0, "enterprise": 0}
	for rows.Next() {
		var id, subject, email, wallet, status, tier, amount string
		var created time.Time
		var verifiedAt, checkedAt, expiresAt sql.NullTime
		if err := rows.Scan(&id, &subject, &email, &wallet, &status, &created, &verifiedAt, &tier, &amount, &checkedAt, &expiresAt); err != nil {
			continue
		}
		counts["total"]++
		if verifiedAt.Valid {
			counts["verified"]++
		}
		if tier == "basic" || tier == "pro" || tier == "enterprise" {
			counts["holders"]++
			counts[tier]++
		}
		item := map[string]any{
			"id": id, "auth_subject": subject, "email": email,
			"wallet_address": wallet, "status": status, "created_at": created,
			"wallet_verified": verifiedAt.Valid, "tier": tier, "amount": amount,
			"security_capabilities": koschSecurityCapabilitiesForTier(tier),
		}
		if verifiedAt.Valid {
			item["verified_at"] = verifiedAt.Time
		}
		if checkedAt.Valid {
			item["checked_at"] = checkedAt.Time
		}
		if expiresAt.Valid {
			item["snapshot_expires_at"] = expiresAt.Time
		}
		users = append(users, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "users": users, "summary": counts,
		"mint_address": configuredKoscheiTokenMint(),
		"thresholds": map[string]string{
			"basic":      tokenTierThresholdEnv("KOSCHEI_TOKEN_TIER_BASIC", "25000"),
			"pro":        tokenTierThresholdEnv("KOSCHEI_TOKEN_TIER_PRO", "250000"),
			"enterprise": tokenTierThresholdEnv("KOSCHEI_TOKEN_TIER_ENTERPRISE", "2000000"),
		},
		"security_policy": map[string]any{
			"version": "kosch-security-v1",
			"authority_model": "access_and_coordination_only",
			"fail_closed": true,
			"never_grants": []string{
				"evidence mutation",
				"verdict override",
				"capability expansion",
				"compiler bypass",
				"Sentinel promotion/deployment authority",
				"integration approval",
			},
		},
	})
}
