package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type actorAcceptanceRequest struct {
	Target       string `json:"target"`
	Address      string `json:"address"`
	Network      string `json:"network"`
	LiveEvidence *bool  `json:"live_evidence,omitempty"`
}

// OwnerActorAcceptance executes the existing wallet-first actor investigation
// collectors and evaluates ACTOR_INVESTIGATION_ENGINE.md section 8 as ten
// explicit pass/fail/not_investigated items. It does not create a numeric score,
// broaden recipient history, or grant AI any verdict authority.
func (h *Handler) OwnerActorAcceptance(w http.ResponseWriter, r *http.Request) {
	var input actorAcceptanceRequest
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
	wallet := target
	switch classification.Type {
	case radarTargetWallet:
	case radarTargetTokenAccount:
		wallet = strings.TrimSpace(classification.TokenOwnerWallet)
		if wallet == "" {
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"ok": false, "error": "token_account_owner_unresolved", "target": target,
				"target_classification": classification,
			})
			return
		}
	default:
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok": false, "error": "wallet_target_required", "target": target,
			"target_classification": classification,
		})
		return
	}
	if h == nil || h.DB == nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Actor defense database is unavailable")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 180*time.Second)
	defer cancel()
	store := services.NewActorDefenseStore(h.DB)
	initial, err := store.LoadPersistentWalletDossier(ctx, wallet, network, 100)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Actor defense dossier could not be assembled")
		return
	}

	liveEnabled := true
	if input.LiveEvidence != nil {
		liveEnabled = *input.LiveEvidence
	}
	coverage := actorDefenseLiveCoverage{Status: "stored_evidence_only", Limitations: []string{}}
	fundingOrigin := services.ActorFundingOrigin{
		Wallet: wallet, Status: "stored_evidence_only", VerificationStatus: "unverified",
		TrailStatus: "not_investigated", IdentityScope: "onchain_wallet_only", Limitations: []string{},
	}
	fundingPersistence := "not_requested"
	if liveEnabled {
		fundingOrigin, fundingPersistence = h.collectActorFundingOrigin(ctx, store, wallet, network)
		coverage = h.collectActorDefenseLiveEvidence(ctx, store, initial)
		if fundingPersistence == "failed" {
			coverage.PersistenceFailures++
			if coverage.Status == "complete" {
				coverage.Status = "partial_persistence"
			}
			coverage.Limitations = append(coverage.Limitations, "Funding-origin evidence could not be persisted.")
		}
	}

	final, err := store.LoadPersistentWalletDossier(ctx, wallet, network, 200)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Actor defense dossier could not be refreshed")
		return
	}
	actorVerdict := services.EvaluateActorDefenseRules(final.Track, final.Evidence)
	verdictPersistence := "persisted"
	if err := store.PersistRuleVerdict(ctx, final.Track, actorVerdict); err != nil {
		verdictPersistence = "failed"
		coverage.PersistenceFailures++
		coverage.Limitations = append(coverage.Limitations, "Deterministic actor verdict could not be persisted.")
	}

	acceptance := services.EvaluateActorAcceptance(services.ActorAcceptanceInput{
		Wallet: wallet, Network: network, TargetKind: "wallet", Dossier: final,
		FundingOrigin: fundingOrigin, Verdict: actorVerdict,
	})
	now := time.Now().UTC()
	behavior := services.EvaluateUnifiedRadarBehavior(
		"", wallet, services.TokenMarketSnapshot{}, services.HolderIntelligence{},
		services.HolderClusterAnalysis{}, services.CreatorSellAcceleration{}, now,
	)
	unifiedVerdict := services.EvaluateUnifiedRadarVerdict(wallet, actorVerdict, behavior)
	unifiedPersistence, unifiedHistory := h.persistUnifiedRadarVerdict(ctx, h.DB, network, "wallet", wallet, unifiedVerdict, behavior)
	evidenceGraph := services.BuildActorEvidenceGraph(final)
	report := map[string]any{
		"ok": true,
		"schema_version": "koschei-unified-wallet-investigation-v1",
		"target": target,
		"wallet": wallet,
		"network": network,
		"generated_at": now.Format(time.RFC3339),
		"analysis_scope": "wallet_actor_investigation",
		"target_classification": classification,
		"final_verdict": unifiedVerdict,
		"final_verdict_persistence": unifiedPersistence,
		"final_verdict_history": unifiedHistory,
		"actor_acceptance": acceptance,
		"full_scan_live_evidence": map[string]any{
			"status": coverage.Status,
			"wallet": wallet,
			"transactions_parsed": coverage.TransactionsParsed,
			"evidence_persisted": coverage.EvidencePersisted,
			"limitations": coverage.Limitations,
		},
		"actor_investigation": map[string]any{
			"wallet": wallet,
			"dossier": final,
			"funding_origin": fundingOrigin,
			"funding_origin_persistence": fundingPersistence,
			"actor_live_evidence": coverage,
			"live_evidence": coverage,
			"evidence_graph": evidenceGraph,
			"rule_verdict": actorVerdict,
			"rule_verdict_persistence": verdictPersistence,
		},
		"behavior_signals": behavior,
		"investigation_output_policy": services.SharedInvestigationOutputPolicy(),
		"evidence_policy": map[string]any{
			"numeric_final_score_disabled": true,
			"numeric_rug_probability_disabled": true,
			"no_evidence_no_claim": true,
			"inferred_watch_only": true,
			"unverified_excluded": true,
			"identity_scope": "onchain_wallet_only",
		},
	}
	attachCanonicalWalletIntegrationCoverage(report)
	snapshotPersistence := "not_signed"
	if unifiedVerdict.Signed && strings.TrimSpace(unifiedVerdict.Signature) != "" {
		snapshotPersistence = "persisted_or_existing"
		if err := h.persistDossierSourceSnapshot(ctx, report); err != nil {
			snapshotPersistence = "failed"
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"schema_version": services.ActorAcceptanceContractVersion,
		"target": target,
		"wallet": wallet,
		"network": network,
		"target_classification": classification,
		"live_evidence": coverage,
		"funding_origin_persistence": fundingPersistence,
		"rule_verdict_persistence": verdictPersistence,
		"final_verdict": unifiedVerdict,
		"dossier_snapshot_persistence": snapshotPersistence,
		"acceptance": acceptance,
	})
}
