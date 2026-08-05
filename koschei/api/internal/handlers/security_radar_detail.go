package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/services"
)

// SecurityRadarDetail returns the complete evidence surface for a premium
// Radar target. It intentionally does not hide module signals or truncate the
// evidence list. Language remains evidence-scoped: creator/deployer metadata
// identifies an observed wallet relation, not a real-world identity or crime.
func (h *Handler) SecurityRadarDetail(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(firstNonEmptyString(r.URL.Query().Get("target"), r.URL.Query().Get("mint"), r.URL.Query().Get("address")))
	if target == "" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "target is required")
		return
	}
	network := strings.TrimSpace(r.URL.Query().Get("network"))
	if network == "" {
		network = "solana-mainnet"
	}
	classification := classifyRadarTarget(r.Context(), target)
	if !radarTargetTokenVerdictAllowed(classification) {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok": false, "error": "target_not_token_mint", "message": radarTargetRejectionMessage(classification),
			"target": target, "target_classification": classification,
			"final_verdict": map[string]any{"risk_index": nil, "risk_level": "unknown", "grade": "-", "signed": false, "verdict": "INSUFFICIENT EVIDENCE"},
		})
		return
	}

	analysis := services.AnalyzeArvisRadars(services.SecurityRadarRequest{Target: target, Network: network, Mode: "manual_detail"})
	bundle := services.EvidenceBackedSecurityRadarBundle(analysis.Bundle)
	arms := services.ArvisArmsFromBundle(bundle)
	if len(arms) == 0 {
		arms = analysis.Arms
	}
	freshFinal := services.ArvisFinalFromBundle(bundle)

	holderRoles := services.ArvisHolderRolesFromBundle(bundle)
	distribution := radarDetailHolderDistributionFromRoles(holderRoles)
	if !holderRoles.Available {
		distribution, holderRoles = radarDetailHolderDistribution(r.Context(), target)
	}
	holderCluster := services.ArvisHolderClusterFromBundle(bundle)
	market := radarDetailMarketSnapshot(r.Context(), target)
	holderIntelligence := services.BuildHolderIntelligence(holderRoles, holderCluster, market, time.Now().UTC())
	sourceContext := h.radarDetailSourceContext(r.Context(), target, network)
	structural := h.radarDetailStructuralContext(r.Context(), target, network)
	persisted := h.radarDetailPersistedVerdict(r.Context(), target)
	final := radarDetailFinalMap(freshFinal, persisted)
	modules := radarDetailModules(arms)
	allEvidence := radarDetailEvidence(arms)
	warning := radarDetailWarning(final, distribution, structural, modules, sourceContext)
	graph := h.radarDetailGraph(r.Context(), target)

	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                  true,
		"schema_version":      "koschei-radar-detail-v2",
		"target":              target,
		"network":             network,
		"generated_at":        time.Now().UTC().Format(time.RFC3339),
		"final_verdict":       final,
		"warning":             warning,
		"holder_distribution": distribution,
		"holder_intelligence": holderIntelligence,
		"holder_cluster":      holderCluster,
		"market":              market,
		"structural_memory":   structural,
		"source_context":      sourceContext,
		"modules":             modules,
		"evidence":            allEvidence,
		"graph":               graph,
		"evidence_policy": map[string]any{
			"hide_verified_details": false,
			"no_evidence_no_claim":  true,
			"creator_wallet_scope":  "source-reported or on-chain relation; not proof of wrongdoing or real-world identity",
			"financial_advice":      false,
		},
	})
}

func radarDetailHolderDistributionFromRoles(roles services.HolderRoleAnalysis) map[string]any {
	if !roles.Available {
		return map[string]any{"available": false, "status": "holder_roles_unavailable", "top_accounts": []any{}}
	}
	out := services.HolderRoleAnalysisMap(roles)
	out["largest_account_balance"] = 0.0
	if len(roles.Accounts) > 0 {
		out["largest_account_balance"] = radarDetailRound(roles.Accounts[0].Balance, 6)
	}
	out["account_scope"] = "Token accounts resolved to owner wallets and owner programs; only positively identified protocol inventory or burn sinks are excluded from holder-risk concentration."
	out["evidence_reused_from_full_scan"] = true
	return out
}

func radarDetailHolderDistribution(parent context.Context, target string) (map[string]any, services.HolderRoleAnalysis) {
	rpcURL := strings.TrimSpace(firstNonEmptyString(os.Getenv("SOLANA_RPC_URL"), os.Getenv("ALCHEMY_SOLANA_RPC_URL")))
	if rpcURL == "" {
		return map[string]any{"available": false, "status": "rpc_not_configured", "top_accounts": []any{}}, services.HolderRoleAnalysis{}
	}
	ctx, cancel := context.WithTimeout(parent, 9*time.Second)
	defer cancel()
	supplyResult, err := services.SolanaGetTokenSupply(ctx, rpcURL, target)
	if err != nil {
		return map[string]any{"available": false, "status": "supply_unavailable", "error": compactRadarDetailError(err), "top_accounts": []any{}}, services.HolderRoleAnalysis{}
	}
	accountsResult, err := services.SolanaGetTokenLargestAccounts(ctx, rpcURL, target)
	if err != nil {
		return map[string]any{"available": false, "status": "largest_accounts_unavailable", "error": compactRadarDetailError(err), "top_accounts": []any{}}, services.HolderRoleAnalysis{}
	}
	supply := radarDetailTokenAmount(supplyResult.Value)
	roles := services.AnalyzeSolanaHolderRoles(ctx, rpcURL, supply, accountsResult.Value)
	out := services.HolderRoleAnalysisMap(roles)
	out["decimals"] = supplyResult.Value.Decimals
	out["largest_account_balance"] = 0.0
	if len(accountsResult.Value) > 0 {
		out["largest_account_balance"] = radarDetailRound(radarDetailTokenAmount(accountsResult.Value[0].SolanaTokenAmount), 6)
	}
	out["account_scope"] = "Token accounts resolved to owner wallets and owner programs; only positively identified protocol inventory or burn sinks are excluded from holder-risk concentration."
	return out, roles
}

func radarDetailMarketSnapshot(parent context.Context, target string) services.TokenMarketSnapshot {
	ctx, cancel := context.WithTimeout(parent, 6*time.Second)
	defer cancel()
	return services.FetchSolanaTokenMarketSnapshot(ctx, target)
}

func radarDetailTokenAmount(value services.SolanaTokenAmount) float64 {
	if value.UIAmount != nil {
		return *value.UIAmount
	}
	if raw := strings.TrimSpace(value.UIAmountString); raw != "" {
		if parsed, err := strconv.ParseFloat(raw, 64); err == nil {
			return parsed
		}
	}
	raw, err := strconv.ParseFloat(strings.TrimSpace(value.Amount), 64)
	if err != nil {
		return 0
	}
	if value.Decimals > 0 {
		raw /= math.Pow10(value.Decimals)
	}
	return raw
}

func (h *Handler) radarDetailSourceContext(ctx context.Context, target, network string) map[string]any {
	out := map[string]any{"available": false, "identity_claimed": false}
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return out
	}
	query := `
		SELECT module_id, event_type, COALESCE(source,''), COALESCE(source_address,''),
		       COALESCE(signature,''), COALESCE(signals,'{}'::jsonb),
		       COALESCE(raw_summary,'{}'::jsonb), created_at
		FROM security_radar_events
		WHERE lower(target)=lower($1) AND network=$2
		ORDER BY CASE WHEN event_type='pumpportal_high_volume_24h' AND created_at >= now()-interval '36 hours' THEN 0 WHEN source='pumpportal' THEN 1 ELSE 2 END, created_at DESC
		LIMIT 1`
	var moduleID, eventType, source, sourceAddress, signature string
	var signalsRaw, summaryRaw []byte
	var createdAt time.Time
	if err := db.QueryRowContext(ctx, query, target, network).Scan(&moduleID, &eventType, &source, &sourceAddress, &signature, &signalsRaw, &summaryRaw, &createdAt); err != nil {
		if err != sql.ErrNoRows && !isMissingRelation(err) {
			out["status"] = "source_context_unavailable"
		}
		return out
	}
	signals := map[string]any{}
	summary := map[string]any{}
	_ = json.Unmarshal(signalsRaw, &signals)
	_ = json.Unmarshal(summaryRaw, &summary)
	creator := radarDetailString(signals, "creator_wallet", "deployer_wallet", "creator")
	if creator == "" && strings.EqualFold(source, "pumpportal") {
		creator = strings.TrimSpace(sourceAddress)
	}
	out["available"] = true
	out["module_id"] = moduleID
	out["event_type"] = eventType
	out["source"] = source
	out["source_address"] = sourceAddress
	out["signature"] = signature
	out["observed_at"] = createdAt.UTC().Format(time.RFC3339)
	out["token_name"] = firstNonEmptyString(radarDetailString(signals, "token_name", "name"), radarDetailString(summary, "name"))
	out["token_symbol"] = firstNonEmptyString(radarDetailString(signals, "token_symbol", "symbol"), radarDetailString(summary, "symbol"))
	out["launch_platform"] = firstNonEmptyString(radarDetailString(signals, "launch_platform"), func() string {
		if strings.EqualFold(source, "pumpportal") {
			return "pump.fun"
		}
		return ""
	}())
	out["creator_wallet"] = creator
	out["creator_label"] = "source-reported creator/deployer wallet"
	out["creator_relation_verified"] = creator != "" && (strings.EqualFold(source, "pumpportal") || strings.EqualFold(eventType, "pumpportal_high_volume_24h"))
	out["creator_scope"] = "launch-source relation only; not proof of fraud, ownership of other wallets, or real-world identity"
	out["volume_24h_usd"] = signals["volume_24h_usd"]
	out["volume_threshold_usd"] = signals["volume_threshold_usd"]
	out["volume_provider"] = signals["volume_provider"]
	out["signals"] = signals
	return out
}

func (h *Handler) radarDetailStructuralContext(ctx context.Context, target, network string) map[string]any {
	out := map[string]any{"available": false}
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return out
	}
	var largest, top10 int
	var hasHolder, mintAuth, freezeAuth, hasAuthority, hasSupply bool
	var tokenSupply sql.NullFloat64
	var holderAt, authorityAt, supplyAt sql.NullTime
	err := db.QueryRowContext(ctx, `
		SELECT largest_holder_pct, top10_holder_pct, has_holder_data,
		       mint_authority_present, freeze_authority_present, has_authority_data,
		       token_supply, has_supply_data,
		       holder_observed_at, authority_observed_at, supply_observed_at
		FROM token_structural_signals
		WHERE lower(target)=lower($1) AND network=$2`, target, network).Scan(
		&largest, &top10, &hasHolder, &mintAuth, &freezeAuth, &hasAuthority,
		&tokenSupply, &hasSupply, &holderAt, &authorityAt, &supplyAt)
	if err != nil {
		return out
	}
	out["available"] = hasHolder || hasAuthority || hasSupply
	out["has_holder_data"] = hasHolder
	out["largest_holder_percentage"] = largest
	out["top_10_holder_percentage"] = top10
	out["has_authority_data"] = hasAuthority
	out["mint_authority_present"] = mintAuth
	out["freeze_authority_present"] = freezeAuth
	out["has_supply_data"] = hasSupply
	if hasSupply && tokenSupply.Valid {
		out["token_supply"] = tokenSupply.Float64
	}
	if holderAt.Valid {
		out["holder_observed_at"] = holderAt.Time.UTC().Format(time.RFC3339)
	}
	if authorityAt.Valid {
		out["authority_observed_at"] = authorityAt.Time.UTC().Format(time.RFC3339)
	}
	if supplyAt.Valid {
		out["supply_observed_at"] = supplyAt.Time.UTC().Format(time.RFC3339)
	}
	return out
}

func (h *Handler) radarDetailPersistedVerdict(ctx context.Context, target string) *services.SecurityRadarVerdictRecord {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return nil
	}
	items, err := services.NewSecurityRadarStore(db).LatestVerdicts(ctx, 100)
	if err != nil {
		return nil
	}
	for i := range items {
		if strings.EqualFold(strings.TrimSpace(items[i].Target), strings.TrimSpace(target)) {
			return &items[i]
		}
	}
	return nil
}

func (h *Handler) radarDetailGraph(ctx context.Context, target string) any {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return map[string]any{"empty": true, "nodes": []any{}, "edges": []any{}}
	}
	graph, err := services.NewSecurityRadarStore(db).LatestGraphForTarget(ctx, target, services.ModuleFinalVerdictEngine)
	if err != nil {
		return map[string]any{"empty": true, "nodes": []any{}, "edges": []any{}}
	}
	return graph
}

func radarDetailFinalMap(fresh services.SecurityRadarFinalVerdict, persisted *services.SecurityRadarVerdictRecord) map[string]any {
	out := map[string]any{
		"grade": fresh.Grade, "risk_index": fresh.RiskIndex, "risk_level": fresh.RiskLevel,
		"verdict": fresh.Verdict, "recommendation": fresh.Recommendation,
		"rule_version": fresh.RuleVersion, "signed": fresh.Signed, "signature": fresh.Signature,
		"source": "fresh_verified_arms",
	}
	if !fresh.Signed {
		return out
	}
	if persisted == nil || !persisted.Signed {
		return out
	}
	out["id"] = persisted.ID
	out["grade"] = persisted.Grade
	out["risk_index"] = persisted.RiskIndex
	out["risk_level"] = persisted.RiskLevel
	out["verdict"] = persisted.Verdict
	out["recommendation"] = persisted.Recommendation
	out["rule_version"] = persisted.RuleVersion
	out["signed"] = persisted.Signed
	out["signature"] = persisted.Signature
	out["signals"] = persisted.Signals
	out["evidence"] = persisted.Evidence
	out["created_at"] = persisted.CreatedAt.UTC().Format(time.RFC3339)
	out["source"] = "persisted_signed_representative"
	return out
}

func radarDetailModules(arms []services.SecurityRadarVerdict) []map[string]any {
	out := make([]map[string]any, 0, len(arms))
	for _, arm := range arms {
		verified := false
		for _, key := range []string{"verified_evidence", "real_onchain_evidence", "real_offchain_evidence"} {
			if value, _ := arm.Signals[key].(bool); value {
				verified = true
			}
		}
		out = append(out, map[string]any{
			"module": arm.Module, "module_id": arm.ModuleID, "grade": arm.Grade,
			"risk_index": arm.RiskIndex, "risk_level": arm.RiskLevel,
			"verdict": arm.Verdict, "recommendation": arm.Recommendation,
			"verified": verified && arm.Signed, "signed": arm.Signed,
			"signals": arm.Signals, "evidence": arm.Evidence,
			"generated_at": arm.GeneratedAt, "signature": arm.Signature,
		})
	}
	return out
}

func radarDetailEvidence(arms []services.SecurityRadarVerdict) []map[string]any {
	out := []map[string]any{}
	for _, arm := range arms {
		for _, evidence := range arm.Evidence {
			if strings.TrimSpace(evidence) == "" {
				continue
			}
			out = append(out, map[string]any{
				"module": arm.Module, "module_id": arm.ModuleID,
				"verified": arm.Signed && radarDetailArmVerified(arm), "text": evidence,
			})
		}
	}
	return out
}

func radarDetailWarning(final, distribution, structural map[string]any, modules []map[string]any, source map[string]any) map[string]any {
	risk := radarDetailNumber(final["risk_index"])
	label := "MONITOR"
	if risk >= 65 {
		label = "HIGH_RISK_WARNING"
	} else if risk >= 35 {
		label = "WARNING"
	}
	reasons := []string{}
	positive := []string{}
	roleAdjusted, _ := distribution["role_adjusted"].(bool)
	blockingRoleGap, _ := distribution["blocking_evidence_gap"].(bool)
	protocolPct := radarDetailNumber(distribution["protocol_controlled_percentage"])
	if blockingRoleGap {
		label = "EVIDENCE_PENDING"
		reasons = append(reasons, "Baskın token hesabının ekonomik rolü çözülemedi; Koschei bu durumda yoğunlaşmayı LOW olarak yorumlamaz ve final karar bekletilir.")
	}
	if roleAdjusted && protocolPct > 0 {
		positive = append(positive, fmt.Sprintf("Ham arzın %.2f%%'si doğrulanmış protokol/bonding-curve envanteri olarak ayrıldı; holder riski dolaşımdaki cüzdan dağılımından hesaplandı.", protocolPct))
	}
	largest := radarDetailNumber(distribution["top_1_percentage"])
	if largest == 0 {
		largest = radarDetailNumber(structural["largest_holder_percentage"])
	}
	top10 := radarDetailNumber(distribution["top_10_percentage"])
	if top10 == 0 {
		top10 = radarDetailNumber(structural["top_10_holder_percentage"])
	}
	if largest >= 50 {
		reasons = append(reasons, fmt.Sprintf("En büyük token hesabı gözlenen arzın yaklaşık %.2f%%'sini kontrol ediyor; ciddi merkezileşme ve exit-liquidity baskısı oluşabilir.", largest))
	} else if largest >= 20 {
		reasons = append(reasons, fmt.Sprintf("En büyük token hesabı gözlenen arzın yaklaşık %.2f%%'sini kontrol ediyor.", largest))
	}
	if top10 >= 75 {
		reasons = append(reasons, fmt.Sprintf("İlk 10 token hesabı gözlenen arzın yaklaşık %.2f%%'sini kontrol ediyor.", top10))
	}
	mintAuth, mintKnown := radarDetailAuthority(modules, structural, "mint_authority_present")
	freezeAuth, freezeKnown := radarDetailAuthority(modules, structural, "freeze_authority_present")
	if mintKnown {
		if mintAuth {
			reasons = append(reasons, "Mint authority açık; ek arz üretme yetkisi devam ediyor.")
		} else {
			positive = append(positive, "Mint authority kapalı/revoked olarak gözlendi.")
		}
	}
	if freezeKnown {
		if freezeAuth {
			reasons = append(reasons, "Freeze authority açık; token hesaplarını dondurma yetkisi devam ediyor.")
		} else {
			positive = append(positive, "Freeze authority kapalı/revoked olarak gözlendi.")
		}
	}
	creator := strings.TrimSpace(fmt.Sprint(source["creator_wallet"]))
	if creator != "" {
		reasons = append(reasons, "Launch kaynağı creator/deployer cüzdan ilişkisi bildirdi: "+creator+". Bu, cüzdan ilişkisini gösterir; tek başına kötü niyet kanıtı değildir.")
	}
	if len(reasons) == 0 {
		reasons = append(reasons, "Doğrulanmış yüksek risk koşulu gözlenmedi; modül kanıtları izlenmeye devam edilmelidir.")
	}
	return map[string]any{
		"label": label, "risk_index": risk, "reasons": reasons, "positive_signals": positive,
		"creator_wallet": creator, "accusation": false,
		"interpretation": "Koschei tokenı ve doğrulanmış zincir üstü ilişkileri işaretler; kişi hakkında suç veya dolandırıcılık iddiası üretmez.",
	}
}

func radarDetailAuthority(modules []map[string]any, structural map[string]any, key string) (bool, bool) {
	if value, ok := structural[key].(bool); ok && structural["has_authority_data"] == true {
		return value, true
	}
	for _, module := range modules {
		signals, _ := module["signals"].(map[string]any)
		if value, ok := signals[key].(bool); ok {
			return value, true
		}
	}
	return false, false
}

func radarDetailArmVerified(arm services.SecurityRadarVerdict) bool {
	for _, key := range []string{"verified_evidence", "real_onchain_evidence", "real_offchain_evidence"} {
		if value, _ := arm.Signals[key].(bool); value {
			return true
		}
	}
	return false
}

func radarDetailString(values map[string]any, keys ...string) string {
	for _, key := range keys {
		if value := strings.TrimSpace(fmt.Sprint(values[key])); value != "" && value != "<nil>" {
			return value
		}
	}
	return ""
}

func radarDetailNumber(value any) float64 {
	switch typed := value.(type) {
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case float64:
		return typed
	case json.Number:
		parsed, _ := typed.Float64()
		return parsed
	case string:
		parsed, _ := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return parsed
	default:
		return 0
	}
}

func radarDetailRound(value float64, digits int) float64 {
	factor := math.Pow10(digits)
	return math.Round(value*factor) / factor
}

func compactRadarDetailError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.TrimSpace(err.Error())
	if len(message) > 180 {
		message = message[:180]
	}
	return message
}
