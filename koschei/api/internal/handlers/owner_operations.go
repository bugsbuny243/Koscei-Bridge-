package handlers

import (
	"database/sql"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"koschei/api/internal/services"
)

// OwnerOperationsStatus is the KOSCH-era owner dashboard contract. It avoids
// legacy checkout, package and entitlement concepts entirely.
func (h *Handler) OwnerOperationsStatus(w http.ResponseWriter, r *http.Request) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	ctx := r.Context()
	summary := map[string]any{
		"total_users": 0, "active_users": 0, "verified_wallets": 0,
		"kosch_holders": 0, "kosch_basic": 0, "kosch_pro": 0, "kosch_enterprise": 0,
		"radar_verdicts_24h": 0, "high_risk_24h": 0, "security_events_24h": 0,
		"open_feedback": 0,
	}
	if db != nil {
		if ownerTableExists(ctx, db, "app_user_profiles") {
			summary["total_users"] = ownerCount(ctx, db, `SELECT count(*) FROM app_user_profiles`)
			summary["active_users"] = ownerCount(ctx, db, `SELECT count(*) FROM app_user_profiles WHERE COALESCE(status,'active')='active'`)
		}
		if ownerTableExists(ctx, db, "verified_wallet_links") {
			summary["verified_wallets"] = ownerCount(ctx, db, `SELECT count(DISTINCT auth_subject) FROM verified_wallet_links WHERE status='active'`)
		}
		if ownerTableExists(ctx, db, "token_access_snapshots") {
			latest := `WITH latest AS (
				SELECT DISTINCT ON (auth_subject) auth_subject, tier, amount_raw
				FROM token_access_snapshots
				WHERE expires_at > now()
				ORDER BY auth_subject, checked_at DESC
			)`
			summary["kosch_holders"] = ownerCount(ctx, db, latest+` SELECT count(*) FROM latest WHERE tier IN ('basic','pro','enterprise')`)
			summary["kosch_basic"] = ownerCount(ctx, db, latest+` SELECT count(*) FROM latest WHERE tier='basic'`)
			summary["kosch_pro"] = ownerCount(ctx, db, latest+` SELECT count(*) FROM latest WHERE tier='pro'`)
			summary["kosch_enterprise"] = ownerCount(ctx, db, latest+` SELECT count(*) FROM latest WHERE tier='enterprise'`)
		}
		if ownerTableExists(ctx, db, "security_radar_verdicts") {
			summary["radar_verdicts_24h"] = ownerCount(ctx, db, `SELECT count(*) FROM security_radar_verdicts WHERE module_id='final_verdict_engine' AND signed=true AND created_at >= now()-interval '24 hours'`)
			summary["high_risk_24h"] = ownerCount(ctx, db, `SELECT count(*) FROM security_radar_verdicts WHERE module_id='final_verdict_engine' AND signed=true AND created_at >= now()-interval '24 hours' AND lower(COALESCE(risk_level,'')) IN ('high','critical')`)
		}
		if ownerTableExists(ctx, db, "security_audit_events") {
			summary["security_events_24h"] = ownerCount(ctx, db, `SELECT count(*) FROM security_audit_events WHERE created_at >= now()-interval '24 hours'`)
		}
		if ownerTableExists(ctx, db, "customer_feedback") {
			summary["open_feedback"] = ownerCount(ctx, db, `SELECT count(*) FROM customer_feedback WHERE status IN ('new','reviewing','planned')`)
		}
	}

	radar := h.securityRadarStreamStats(ctx)
	radarStatus := firstMapString(radar, "pipeline_status")
	radar["automatic_scanning"] = services.AutomaticBackgroundScanningEnabled()
	radar["unlimited_owner_test_mode"] = services.OwnerUnlimitedAutomaticScanningEnabled()
	if services.OwnerUnlimitedAutomaticScanningEnabled() {
		radarStatus = "owner_auto_unlimited"
		radar["background_streams_paused"] = false
		radar["local_rpc_budget_enabled"] = false
		radar["report_cycle_limit"] = nil
		radar["pipeline_status"] = radarStatus
	} else if strings.EqualFold(strings.TrimSpace(os.Getenv("SOLANA_RPC_LIMIT_SAVER_ENABLED")), "true") {
		radar["background_streams_paused"] = true
		radar["manual_scans_available"] = true
		if services.PumpHighVolumeRadarEnabled() {
			radarStatus = "selective_auto_volume"
			radar["pump_volume_auto_enabled"] = true
			radar["pump_volume_threshold_usd"] = services.PumpHighVolumeThresholdUSD()
		} else {
			radarStatus = "manual_rpc_saver"
		}
		radar["pipeline_status"] = radarStatus
	}
	servicesMap := map[string]any{
		"database":        map[string]any{"status": serviceStatus(db != nil, "connected", "unavailable")},
		"neon_auth":       map[string]any{"status": serviceStatus(envSet("NEON_AUTH_JWKS_URL"), "configured", "missing")},
		"solana_rpc":      map[string]any{"status": serviceStatus(envSet("SOLANA_RPC_URL") || envSet("ALCHEMY_SOLANA_RPC_URL") || envSet("HELIUS_SOLANA_RPC_URL") || envSet("QUICKNODE_SOLANA_RPC_URL") || envSet("ALCHEMY_API_KEY"), "configured", "missing")},
		"security_radar":  map[string]any{"status": radarStatus},
		"kosch_access":    map[string]any{"status": serviceStatus(configuredKoscheiTokenGateEnabled() && configuredKoscheiTokenMint() != "", "configured", "missing")},
		"visual_renderer": map[string]any{"status": "ready", "mode": "client_canvas_png"},
		"owner_brain":     map[string]any{"status": serviceStatus(aiProviderConfigured(), "configured", "missing")},
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "generated_at": time.Now().UTC(), "summary": summary,
		"services": servicesMap, "radar": radar,
		"access_model": map[string]any{
			"free_core":         []string{"safe_check", "basic_token_scan"},
			"kosch_premium":     []string{"full_radar", "structural_memory", "graph", "exposure", "visual_reports", "automation"},
			"payment_providers": []string{},
		},
	})
}

// OwnerRadarOverview powers the owner ARVIS workspace without requiring a
// customer KOSCH session. The owner cookie remains mandatory at route level.
func (h *Handler) OwnerRadarOverview(w http.ResponseWriter, r *http.Request) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	items := []services.SecurityRadarVerdictRecord{}
	sources := []services.SecurityRadarSource{}
	highVolumePump := []services.PumpHighVolumeOwnerItem{}
	if db != nil {
		store := services.NewSecurityRadarStore(db)
		if loaded, err := store.LatestVerdicts(r.Context(), 100); err == nil {
			items = loaded
		}
		if loaded, err := store.ListSources(r.Context()); err == nil {
			sources = loaded
		}
		if loaded, err := store.LatestPumpHighVolumeReports(r.Context(), 200); err == nil {
			highVolumePump = loaded
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "generated_at": time.Now().UTC(), "items": items,
		"high_volume_pump": highVolumePump,
		"sources":          sources, "pipeline": h.securityRadarStreamStats(r.Context()),
	})
}

// OwnerRadarScan executes the complete evidence pipeline and joins the original
// 14 ARVIS arms, persistent actor investigation and the four versioned behavior
// rules in one manual dossier. Numeric legacy output is retained only as an
// evidence appendix; the authoritative final verdict is deterministic and
// letter-based.
func (h *Handler) OwnerRadarScan(w http.ResponseWriter, r *http.Request) {
	var input securityRadarInput
	if err := decodeJSON(r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Invalid request body")
		return
	}
	target := strings.TrimSpace(firstNonEmptyString(input.Target, input.Address))
	if target == "" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "target is required")
		return
	}
	network := strings.TrimSpace(input.Network)
	if network == "" {
		network = "solana-mainnet"
	}
	classification := classifyRadarTarget(r.Context(), target)
	if !radarTargetTokenVerdictAllowed(classification) {
		statusCode := http.StatusUnprocessableEntity
		if classification.Type == radarTargetUnknown {
			statusCode = http.StatusServiceUnavailable
		}
		writeJSON(w, statusCode, map[string]any{
			"ok": false, "error": "token_mint_required", "charged": false,
			"target": target, "network": network, "target_classification": classification,
			"analysis_scope": classification.Type, "report_status": "insufficient_evidence",
			"message": radarTargetRejectionMessage(classification),
			"final_verdict": map[string]any{
				"grade": "-", "risk_index": nil, "risk_level": "unknown", "signed": false,
				"verdict":        "INSUFFICIENT EVIDENCE: token-mint verdict is not applicable to this target type.",
				"recommendation": classification.Type + "_intelligence_required",
			},
		})
		return
	}
	core := h.runHolderIntelligenceCore(r.Context(), target, network, "owner_full_scan")
	bundle := core.Bundle
	distribution := core.Distribution
	holderCluster := core.Cluster
	sourceContext := core.SourceContext
	launchForensics := core.LaunchForensics
	if services.SecurityRadarHasLiveEvidence(bundle) {
		_ = h.saveSecurityRadarBundle(r.Context(), ownerChatIdentity(), "owner_full_scan", bundle)
	}
	arms := core.Arms
	freshFinal := core.Final
	market := core.Market
	holderIntelligence := core.Intelligence
	structural := h.radarDetailStructuralContext(r.Context(), target, network)
	persisted := h.radarDetailPersistedVerdict(r.Context(), target)
	legacyFinal := radarDetailFinalMap(freshFinal, persisted)
	modules := radarDetailModules(arms)
	evidence := radarDetailEvidence(arms)
	warning := radarDetailWarning(legacyFinal, distribution, structural, modules, sourceContext)
	graph := h.radarDetailGraph(r.Context(), target)
	unified := h.buildOwnerUnifiedRadarOverlay(r.Context(), target, network, core)

	detail := map[string]any{
		"ok": true, "schema_version": "koschei-owner-radar-v3", "target": target,
		"network": network, "generated_at": time.Now().UTC().Format(time.RFC3339),
		"target_classification": classification, "analysis_scope": radarTargetTokenMint,
		"final_verdict":                    unified.FinalVerdict,
		"legacy_arvis_final":               legacyFinal,
		"numeric_score_authoritative":      false,
		"numeric_score_disabled_for_final": true,
		"ruleset_version":                  unified.FinalVerdict.RulesetVersion,
		"unified_radar":                    unified,
		"warning":                          warning, "holder_distribution": distribution,
		"holder_intelligence": holderIntelligence, "holder_cluster": holderCluster, "launch_forensics": launchForensics, "market": market,
		"structural_memory": structural, "source_context": sourceContext,
		"modules": modules, "evidence": evidence, "graph": graph,
		"evidence_policy": map[string]any{
			"hide_verified_details": false, "no_evidence_no_claim": true,
			"creator_wallet_scope":   "source-reported or on-chain relation; not proof of wrongdoing or real-world identity",
			"financial_advice":       false,
			"automatic_scanning":     false,
			"manual_scan_only":       true,
			"inferred_is_watch_only": true,
			"unverified_is_excluded": true,
		},
	}
	explanationV2 := holderIntelligenceCoreExplanationV2(core)
	detail["legacy_primary_risk_driver"] = ownerRadarPrimaryRiskDriver(modules)
	if len(unified.FinalVerdict.TriggeredRules) > 0 {
		detail["primary_risk_driver"] = unified.FinalVerdict.TriggeredRules[0]
	} else {
		detail["primary_risk_driver"] = nil
	}
	detail["legacy_explanation_v2"] = explanationV2
	detail["legacy_narrative"] = explanationV2.Text
	detail["narrative"] = unified.Narrative
	writeJSON(w, http.StatusOK, detail)
}

func ownerRadarModuleSignal(modules []map[string]any, moduleID, key string) any {
	for _, module := range modules {
		if !strings.EqualFold(strings.TrimSpace(fmt.Sprint(module["module_id"])), moduleID) {
			continue
		}
		signals, _ := module["signals"].(map[string]any)
		if signals != nil {
			return signals[key]
		}
	}
	return nil
}

func ownerRadarNarrative(target string, final, warning, distribution, source map[string]any, modules []map[string]any, holder services.HolderIntelligence, launch services.LaunchForensicsAnalysis) string {
	signed, _ := final["signed"].(bool)
	explanation := buildScanExplanationV2(scanExplanationInput{
		Target:    target,
		RiskIndex: radarDetailNumber(final["risk_index"]),
		RiskLevel: strings.TrimSpace(fmt.Sprint(final["risk_level"])),
		Signed:    signed,
		Policy: func() string {
			if signed {
				return "evidence_backed"
			}
			return "withhold"
		}(),
		Distribution: distribution,
		Warning:      warning,
		Holder:       holder,
		Launch:       launch,
		Modules:      modules,
	})
	return explanation.Text
}

func ownerRadarPendingNarrative(target string, holder services.HolderIntelligence, distribution, warning map[string]any) string {
	parts := []string{
		"Koschei bu hedef için doğrulanmış bir final risk puanı üretmedi; bu, elde veri olmadığı veya tokenın güvenli olduğu anlamına gelmez.",
	}
	if holder.Available {
		parts = append(parts, fmt.Sprintf("Zincir üstü holder yüzeyi yine doğrulandı: toplam arz %.4f token, owner bazında %d kontrol yüzeyi ve %d risk taşıyan owner gözlendi.", holder.Supply, holder.OwnerCount, holder.RiskBearingOwnerCount))
		if len(holder.Rows) > 0 {
			top := holder.Rows[0]
			owner := top.OwnerWallet
			if owner == "" && len(top.TokenAccounts) > 0 {
				owner = top.TokenAccounts[0]
			}
			usd := ""
			if top.ReferenceUSDValue != nil {
				usd = fmt.Sprintf("; referans piyasa değeri yaklaşık $%.2f", *top.ReferenceUSDValue)
			}
			parts = append(parts, fmt.Sprintf("En büyük gözlenen hesap %s üzerinde %.4f token tutuyor ve owner-bazlı arz payı yaklaşık %.4f%%%s.", ownerRadarShortTarget(owner), top.Balance, holder.TopOwnerPercentage, usd))
			if !top.OwnerResolved || strings.Contains(top.Role, "unresolved") || top.Role == "wallet_account_unavailable" {
				parts = append(parts, "Bu baskın hesabın owner veya ekonomik rolü çözülemediği için Koschei yüksek yoğunluğu saklamadı fakat wallet-control finali de uydurmadı; sonuç bu nedenle EVIDENCE PENDING kaldı.")
			}
		}
		if holder.Market.Available {
			parts = append(parts, fmt.Sprintf("Piyasa bağlamı: referans fiyat $%.10f, 24 saatlik hacim $%.2f, likidite $%.2f ve piyasa değeri $%.2f.", holder.Market.PriceUSD, holder.Market.Volume24hUSD, holder.Market.LiquidityUSD, holder.Market.MarketCapUSD))
		}
		if holder.WalletsWithObservedOutflow > 0 {
			parts = append(parts, fmt.Sprintf("Sınırlı cüzdan geçmişinde %d holder wallet için hedef-token çıkışı gözlendi.", holder.WalletsWithObservedOutflow))
		}
		if holder.CommonExitGroupCount > 0 {
			parts = append(parts, fmt.Sprintf("%d ortak recipient-owner çıkış grubu doğrulandı; bu ilişki tek başına ortak sahiplik, satış veya wash trading kanıtı değildir.", holder.CommonExitGroupCount))
		}
	}
	for _, reason := range ownerRadarStringSlice(warning["reasons"]) {
		if strings.TrimSpace(reason) != "" {
			parts = append(parts, reason)
		}
	}
	parts = append(parts, "Final skor için eksik rol ve modül kanıtları tamamlanmalıdır; mevcut gerçek bakiyeler, yüzdeler ve davranış gözlemleri aşağıdaki holder tablosunda gösterilir.")
	return strings.Join(parts, " ")
}

func ownerRadarPrimaryRiskDriver(modules []map[string]any) map[string]any {
	var best map[string]any
	bestRisk := -1.0
	for _, module := range modules {
		moduleID := strings.ToLower(strings.TrimSpace(fmt.Sprint(module["module_id"])))
		if moduleID == "" || moduleID == "final_verdict_engine" {
			continue
		}
		verified, _ := module["verified"].(bool)
		signed, _ := module["signed"].(bool)
		if !verified || !signed {
			continue
		}
		risk := radarDetailNumber(module["risk_index"])
		if risk > bestRisk {
			bestRisk = risk
			best = module
		}
	}
	return best
}

func ownerRadarStringSlice(raw any) []string {
	out := []string{}
	switch values := raw.(type) {
	case []string:
		for _, value := range values {
			if value = strings.TrimSpace(value); value != "" {
				out = append(out, value)
			}
		}
	case []any:
		for _, rawValue := range values {
			if value := strings.TrimSpace(fmt.Sprint(rawValue)); value != "" && value != "<nil>" {
				out = append(out, value)
			}
		}
	}
	return out
}

func ownerRadarShortTarget(target string) string {
	target = strings.TrimSpace(target)
	if len(target) <= 18 {
		return target
	}
	return target[:9] + "…" + target[len(target)-7:]
}

func ownerRadarRiskLabelTR(level string) string {
	switch level {
	case "critical":
		return "KRİTİK"
	case "high":
		return "YÜKSEK"
	case "medium":
		return "ORTA"
	case "low":
		return "DÜŞÜK"
	default:
		return strings.ToUpper(level)
	}
}

func ownerRadarRiskMeaning(level string) string {
	switch level {
	case "critical", "high":
		return "Bu seviye, doğrulanmış risk sinyallerinin işlem öncesinde ayrıntılı biçimde incelenmesi gerektiğini gösterir; otomatik olarak rug veya dolandırıcılık hükmü değildir."
	case "medium":
		return "Bu seviye doğrudan rug kanıtı değildir; bazı risk kollarının temiz görünürken en az bir doğrulanmış modülün ek inceleme istediğini gösterir."
	case "low":
		return "Bu seviye mevcut kanıtlarda ağır bir risk sürücüsü görülmediğini gösterir; yine de düşük risk, risksiz anlamına gelmez."
	default:
		return "Karar yalnızca mevcut ve doğrulanmış kanıtların kapsamını yansıtır."
	}
}

func ownerRadarRoleTR(role string) string {
	switch role {
	case "externally_owned_wallet":
		return "normal kullanıcı cüzdanı"
	case "pump_bonding_curve_or_protocol_vault":
		return "Pump bonding-curve/protokol kasası"
	case "pump_liquidity_vault":
		return "Pump likidite kasası"
	case "burn_sink":
		return "burn adresi"
	case "program_controlled_unresolved":
		return "rolü henüz çözülememiş program kontrollü hesap"
	default:
		if role == "" || role == "<nil>" {
			return "belirlenemeyen hesap"
		}
		return strings.ReplaceAll(role, "_", " ")
	}
}

func ownerRadarHolderMeaning(top1, top10 float64) string {
	switch {
	case top1 < 5 && top10 < 25:
		return "Bu dağılım tek başına ciddi bir balina veya arz merkezileşmesi göstermiyor; holder tarafı görece dengeli görünüyor."
	case top1 < 15 && top10 < 50:
		return "Holder dağılımı belirgin bir tek-cüzdan hâkimiyeti göstermiyor, ancak büyük hesapların hareketleri izlenmeye devam edilmelidir."
	case top1 >= 50:
		return "Tek bir risk taşıyan cüzdan arzın yarısından fazlasını kontrol ediyor; satış hâlinde ciddi fiyat ve exit-liquidity baskısı oluşabilir."
	case top1 >= 20 || top10 >= 75:
		return "Holder dağılımı merkezileşmiş görünüyor; büyük cüzdanların satış ve bağlantı geçmişi çözülmeden güvenli kabul edilmemelidir."
	default:
		return "Holder yoğunluğu orta seviyede; tek başına nihai karar vermek için creator, likidite, funding cluster ve zamanlama kanıtlarıyla birlikte okunmalıdır."
	}
}

func ownerRadarPracticalConclusion(level string, distribution map[string]any) string {
	available, _ := distribution["available"].(bool)
	if available {
		top1 := radarDetailNumber(distribution["top_1_percentage"])
		top10 := radarDetailNumber(distribution["top_10_percentage"])
		switch {
		case top1 >= 50:
			return "Pratik sonuç: tek bir risk taşıyan cüzdan dolaşımdaki arzın yarısından fazlasını kontrol ediyor. Bu cüzdanın satış, transfer, funding ve ortak-exit geçmişi çözülmeden token güvenli kabul edilmemelidir."
		case top1 >= 20 || top10 >= 75:
			return "Pratik sonuç: holder dağılımı merkezileşmiş durumda. Büyük cüzdanların satış kapasitesi, likidite çıkış yolları ve cluster bağlantıları işlem öncesinde doğrulanmalıdır."
		}
	}
	switch level {
	case "critical", "high":
		return "Pratik sonuç: işlem yapmadan önce ana risk sürücüsünün kanıtlarını, likidite çıkış yollarını, creator geçmişini ve bağlı cüzdan kümelerini doğrulamak gerekir."
	case "medium":
		return "Pratik sonuç: token otomatik olarak güvenli sayılmaz. Ana risk modülü, likidite davranışı, creator geçmişi ve Sybil/funding-cluster bağlantıları birlikte incelenmelidir."
	case "low":
		return "Pratik sonuç: mevcut taramada ağır bir alarm yok; yine de likidite, creator ve cüzdan kümeleri değişebileceği için karar güncel verilerle yenilenmelidir."
	default:
		return "Pratik sonuç: kanıt kapsamı tamamlanmadan kesin güvenlik yorumu yapılmamalıdır."
	}
}

// OwnerKOSCHAccess exposes current wallet verification and the latest cached
// KOSCH tier per account. Historical package/credit fields are intentionally
// absent from this contract.
func (h *Handler) OwnerKOSCHAccess(w http.ResponseWriter, r *http.Request) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil || !ownerTableExists(r.Context(), db, "app_user_profiles") {
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "users": []any{}, "summary": map[string]any{}})
		return
	}
	q := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("q")))
	walletJoin := `LEFT JOIN LATERAL (SELECT wallet_address, verified_at FROM verified_wallet_links v WHERE v.auth_subject=p.auth_subject AND v.status='active' ORDER BY verified_at DESC LIMIT 1) vw ON true`
	if !ownerTableExists(r.Context(), db, "verified_wallet_links") {
		walletJoin = `LEFT JOIN LATERAL (SELECT NULL::text wallet_address, NULL::timestamptz verified_at) vw ON true`
	}
	snapshotJoin := `LEFT JOIN LATERAL (SELECT tier, amount, amount_raw, checked_at, expires_at FROM token_access_snapshots s WHERE s.auth_subject=p.auth_subject ORDER BY checked_at DESC LIMIT 1) ts ON true`
	if !ownerTableExists(r.Context(), db, "token_access_snapshots") {
		snapshotJoin = `LEFT JOIN LATERAL (SELECT NULL::text tier, NULL::text amount, NULL::text amount_raw, NULL::timestamptz checked_at, NULL::timestamptz expires_at) ts ON true`
	}
	rows, err := db.QueryContext(r.Context(), `
		SELECT p.id::text, COALESCE(p.auth_subject,''), lower(p.email),
		       COALESCE(NULLIF(vw.wallet_address,''),NULLIF(p.wallet_address,''),''),
		       COALESCE(p.status,'active'), p.created_at,
		       vw.verified_at, COALESCE(ts.tier,'none'), COALESCE(ts.amount,'0'),
		       ts.checked_at, ts.expires_at
		FROM app_user_profiles p
		`+walletJoin+`
		`+snapshotJoin+`
		WHERE ($1='' OR lower(p.email) LIKE $2 OR lower(COALESCE(p.auth_subject,'')) LIKE $2 OR lower(COALESCE(vw.wallet_address,p.wallet_address,'')) LIKE $2)
		ORDER BY p.created_at DESC LIMIT 500`, q, "%"+q+"%")
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
		item := map[string]any{"id": id, "auth_subject": subject, "email": email, "wallet_address": wallet, "status": status, "created_at": created, "wallet_verified": verifiedAt.Valid, "tier": tier, "amount": amount}
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
			"basic":      tokenTierThresholdEnv("KOSCHEI_TOKEN_TIER_BASIC", "0.000001"),
			"pro":        tokenTierThresholdEnv("KOSCHEI_TOKEN_TIER_PRO", "250000"),
			"enterprise": tokenTierThresholdEnv("KOSCHEI_TOKEN_TIER_ENTERPRISE", "2000000"),
		},
	})
}
