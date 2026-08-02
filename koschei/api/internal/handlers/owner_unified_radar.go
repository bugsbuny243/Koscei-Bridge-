package handlers

import (
	"context"
	"database/sql"
	"log"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type ownerUnifiedRadarRequest struct {
	Target        string `json:"target"`
	Address       string `json:"address"`
	Network       string `json:"network"`
	LiveEvidence  *bool  `json:"live_evidence,omitempty"`
	Court         *bool  `json:"court,omitempty"`
	ExtendedCourt *bool  `json:"extended_court,omitempty"`
}

// OwnerUnifiedRadarScan is the owner-facing manual entry point. Token targets
// use the same technical investigation report as public and API callers.
func (h *Handler) OwnerUnifiedRadarScan(w http.ResponseWriter, r *http.Request) {
	var input ownerUnifiedRadarRequest
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
	budgets := services.LoadArvisScanBudgets()
	log.Printf("arvis scan budgets: wallet=%ds launch=%ds creator=%ds rpc=%d funding=%d", budgets.WalletTimeoutSeconds, budgets.LaunchTimeoutSeconds, budgets.CreatorTimeoutSeconds, budgets.RPCBudget, budgets.FundingRPCBudget)
	courtRequested := envBool("KOSCHEI_OWNER_COURT_AUTO_ENABLED", false)
	if input.Court != nil {
		courtRequested = *input.Court
	}
	extendedCourt := envBool("KOSCHEI_OWNER_COURT_EXTENDED", false)
	if input.ExtendedCourt != nil {
		extendedCourt = *input.ExtendedCourt
	}
	classification := classifyRadarTarget(r.Context(), target)
	switch classification.Type {
	case radarTargetTokenMint:
		h.ownerUnifiedTokenRadar(w, r, target, network, classification, courtRequested, extendedCourt)
	case radarTargetWallet, radarTargetTokenAccount:
		wallet := target
		if classification.Type == radarTargetTokenAccount {
			wallet = strings.TrimSpace(classification.TokenOwnerWallet)
		}
		if wallet == "" {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"ok": false, "error": "token_account_owner_unresolved",
				"target": target, "target_classification": classification,
				"message": "Token hesabının owner cüzdanı çözümlenemedi; birleşik Radar başlatılmadı.",
			})
			return
		}
		liveEvidence := true
		if input.LiveEvidence != nil {
			liveEvidence = *input.LiveEvidence
		}
		h.ownerUnifiedWalletRadar(w, r, target, wallet, network, classification, liveEvidence, courtRequested, extendedCourt)
	default:
		status := http.StatusUnprocessableEntity
		if classification.Type == radarTargetUnknown {
			status = http.StatusServiceUnavailable
		}
		writeJSON(w, status, map[string]any{
			"ok": false, "error": "unsupported_radar_target", "target": target,
			"network": network, "target_classification": classification,
			"message": "Tek Radar şu anda doğrulanmış token mint, wallet veya token-account hedefini kabul eder.",
		})
	}
}

func (h *Handler) ownerUnifiedTokenRadar(w http.ResponseWriter, r *http.Request, target, network string, classification radarTargetClassification, courtRequested, extendedCourt bool) {
	timeout := 180 * time.Second
	if courtRequested {
		timeout = 360 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	assembly := h.buildUnifiedInvestigationReport(ctx, target, network, "owner_unified_manual_scan")
	core := assembly.Core
	if services.SecurityRadarHasLiveEvidence(core.Bundle) {
		_ = h.saveSecurityRadarBundle(ctx, ownerChatIdentity(), "owner_unified_manual_scan", core.Bundle)
	}

	behaviorPersistence := "not_applicable"
	if assembly.Store != nil && len(assembly.Behavior.Evidence) > 0 {
		behaviorPersistence = "persisted"
		for _, item := range assembly.Behavior.Evidence {
			item.Network = network
			if err := assembly.Store.UpsertEvidence(ctx, item); err != nil {
				behaviorPersistence = "partial_failure"
			}
		}
	}
	actorVerdictPersistence := "not_applicable"
	if assembly.Store != nil && strings.TrimSpace(assembly.ActorTrack.TargetID) != "" {
		actorVerdictPersistence = "persisted"
		if err := assembly.Store.PersistRuleVerdict(ctx, assembly.ActorTrack, assembly.ActorVerdict); err != nil {
			actorVerdictPersistence = "failed"
		}
	}
	unifiedPersistence, unifiedHistory := h.persistUnifiedRadarVerdict(ctx, assembly.DB, network, "token", target, assembly.UnifiedVerdict, assembly.Behavior)

	report := assembly.Report
	scannedAt := time.Now().UTC()
	if generated, ok := report["generated_at"].(string); ok {
		if parsed, err := time.Parse(time.RFC3339, generated); err == nil {
			scannedAt = parsed
		}
	}
	report["target_identity"] = services.BuildTargetIdentity(target, core.Market, scannedAt)
	report["target_classification"] = classification
	report["manual_only"] = true
	report["automatic_scanning"] = false
	report["final_verdict_persistence"] = unifiedPersistence
	report["final_verdict_history"] = unifiedHistory
	report["behavior_evidence_persistence"] = behaviorPersistence
	if actor, ok := report["actor_investigation"].(map[string]any); ok {
		actor["rule_verdict_persistence"] = actorVerdictPersistence
	}
	legacyFinal := radarDetailFinalMap(core.Final, h.radarDetailPersistedVerdict(ctx, target))
	report["legacy_14_arm_radar"] = map[string]any{
		"architecture_arm_count": 14,
		"investigation_coverage": services.BuildArvisInvestigationCoverage(core.Arms),
		"final_verdict":          legacyFinal,
		"warning":                radarDetailWarning(legacyFinal, core.Distribution, assembly.Structural, assembly.Modules, core.SourceContext),
		"holder_distribution":    core.Distribution,
		"holder_intelligence":    core.Intelligence,
		"holder_cluster":         core.Cluster,
		"launch_forensics":       core.LaunchForensics,
		"market":                 core.Market,
		"structural_memory":      assembly.Structural,
		"source_context":         core.SourceContext,
		"modules":                assembly.Modules,
		"evidence":               radarDetailEvidence(core.Arms),
		"graph":                  assembly.Graph,
	}

	// Optional model orchestration remains an internal, read-only appendix. It is
	// not part of the canonical technical result and cannot change the verdict.
	if courtRequested {
		courtInput := CourtReadOnlyInput{
			Target: target, Network: network, SignedVerdict: assembly.UnifiedVerdict,
			VerdictCard: map[string]any{"grade": assembly.UnifiedVerdict.Grade, "verdict": assembly.UnifiedVerdict.Verdict, "signed": assembly.UnifiedVerdict.Signed, "signature": assembly.UnifiedVerdict.Signature},
			EvidencePacket: map[string]any{
				"threat_anticipation": assembly.Threat, "behavior_signals": assembly.Behavior,
				"actor_rule_verdict": assembly.ActorVerdict, "actor_evidence": assembly.CombinedEvidence,
				"holder_intelligence": core.Intelligence, "holder_cluster": core.Cluster,
				"market": core.Market, "modules": assembly.Modules,
				"evidence": radarDetailEvidence(core.Arms), "graph": assembly.Graph,
			},
		}
		courtCtx := context.WithValue(ctx, courtTierOverrideKey{}, "enterprise")
		if appendix := h.courtNarrative(courtCtx, courtInput, extendedCourt); appendix != nil {
			report["independent_review"] = appendix
		}
	}
	writeJSON(w, http.StatusOK, report)
}

func (h *Handler) ownerUnifiedWalletRadar(w http.ResponseWriter, r *http.Request, requestedTarget, wallet, network string, classification radarTargetClassification, liveEvidence, courtRequested, extendedCourt bool) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Unified Radar database is unavailable")
		return
	}
	timeout := 180 * time.Second
	if courtRequested {
		timeout = 360 * time.Second
	}
	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()
	store := services.NewActorDefenseStore(db)
	initial, err := store.LoadPersistentWalletDossier(ctx, wallet, network, 150)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Actor dossier could not be assembled")
		return
	}
	coverage := actorDefenseLiveCoverage{Status: "stored_evidence_only", Limitations: []string{}}
	funding := services.ActorFundingOrigin{Wallet: wallet, Status: "stored_evidence_only", VerificationStatus: "unverified", TrailStatus: "not_investigated", IdentityScope: "onchain_wallet_only", Limitations: []string{}}
	fundingPersistence := "not_requested"
	externalDiscovery := newActorExternalDiscoveryRun(wallet)
	working := initial
	if liveEvidence {
		externalDiscovery = h.collectActorExternalDiscovery(ctx, store, wallet, network)
		funding, fundingPersistence = h.collectActorFundingOrigin(ctx, store, wallet, network)
		if refreshed, refreshErr := store.LoadPersistentWalletDossier(ctx, wallet, network, 200); refreshErr == nil {
			working = refreshed
		}
		coverage = h.collectActorDefenseLiveEvidence(ctx, store, working)
	}
	final, err := store.LoadPersistentWalletDossier(ctx, wallet, network, 250)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Actor dossier could not be refreshed")
		return
	}
	actorVerdict := services.EvaluateActorDefenseRules(final.Track, final.Evidence)
	persistence := "persisted"
	if err := store.PersistRuleVerdict(ctx, final.Track, actorVerdict); err != nil {
		persistence = "failed"
	}
	behavior := services.EvaluateUnifiedRadarBehavior("", wallet, services.TokenMarketSnapshot{}, services.HolderIntelligence{}, services.HolderClusterAnalysis{}, services.CreatorSellAcceleration{}, time.Now().UTC())
	unifiedVerdict := services.EvaluateUnifiedRadarVerdict(wallet, actorVerdict, behavior)
	unifiedPersistence, unifiedHistory := h.persistUnifiedRadarVerdict(ctx, db, network, "wallet", wallet, unifiedVerdict, behavior)
	response := map[string]any{
		"ok": true, "schema_version": "koschei-unified-investigation-v1",
		"target": requestedTarget, "wallet": wallet, "network": network,
		"generated_at":          time.Now().UTC().Format(time.RFC3339),
		"target_classification": classification, "analysis_scope": "wallet_actor_investigation",
		"manual_only": true, "automatic_scanning": false,
		"final_verdict":             unifiedVerdict,
		"final_verdict_persistence": unifiedPersistence,
		"final_verdict_history":     unifiedHistory,
		"legacy_14_arm_radar":       map[string]any{"applicable": false, "reason": "Token-specific collectors are not fabricated for a wallet-only target.", "modules": []any{}},
		"actor_investigation": map[string]any{
			"wallet": wallet, "dossier": final, "external_discovery": externalDiscovery,
			"funding_origin": funding, "funding_origin_persistence": fundingPersistence,
			"live_evidence": coverage, "rule_verdict": actorVerdict,
			"rule_verdict_persistence": persistence,
		},
		"behavior_signals":            behavior,
		"investigation_output_policy": services.SharedInvestigationOutputPolicy(),
		"evidence_policy": map[string]any{
			"numeric_final_score_disabled": true, "no_evidence_no_claim": true,
			"inferred_watch_only": true, "unverified_excluded": true,
			"external_attribution_is_observed_only": true,
			"identity_scope":                        "onchain_wallet_only", "caller_type_changes_evidence": false,
		},
	}
	writeJSON(w, http.StatusOK, response)
}

func ownerCourtUnavailableReport(status string) *CourtReport {
	return &CourtReport{
		Status:      status,
		TierApplied: "enterprise",
		Authority:   "the signed deterministic verdict is final; model output is commentary/explanation",
		GeneratedAt: time.Now().UTC(),
	}
}

func (h *Handler) persistUnifiedRadarVerdict(ctx context.Context, db *sql.DB, network, targetKind, targetID string, verdict services.UnifiedRadarVerdict, behavior services.UnifiedRadarBehaviorReport) (string, []services.UnifiedRadarVerdictHistoryRecord) {
	if db == nil {
		return "database_unavailable", []services.UnifiedRadarVerdictHistoryRecord{}
	}
	store := services.NewUnifiedRadarVerdictStore(db)
	status := "persisted"
	if _, err := store.Persist(ctx, network, targetKind, targetID, verdict, behavior); err != nil {
		status = "failed"
	}
	history, err := store.History(ctx, network, targetKind, targetID, 20)
	if err != nil {
		if status == "persisted" {
			status = "history_read_failed"
		}
		return status, []services.UnifiedRadarVerdictHistoryRecord{}
	}
	return status, history
}
