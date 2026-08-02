package handlers

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type customerWalletInvestigationResult struct {
	Target                string
	Wallet                string
	Network               string
	Classification        radarTargetClassification
	Dossier               services.ActorDefenseDossier
	FundingOrigin         services.ActorFundingOrigin
	FundingPersistence    string
	LiveCoverage          actorDefenseLiveCoverage
	RuleVerdict           services.ActorDefenseRuleVerdict
	RulePersistence       string
	HasLiveEvidence       bool
	HasPersistentEvidence bool
	PublishedResult       bool
}

func radarTargetWalletInvestigationAllowed(classification radarTargetClassification) bool {
	if classification.Type == radarTargetWallet {
		return true
	}
	return classification.Type == radarTargetTokenAccount && strings.TrimSpace(classification.TokenOwnerWallet) != ""
}

func resolveCustomerWalletTarget(target string, classification radarTargetClassification) (string, error) {
	switch classification.Type {
	case radarTargetWallet:
		wallet := strings.TrimSpace(target)
		if wallet == "" {
			return "", fmt.Errorf("wallet target is empty")
		}
		return wallet, nil
	case radarTargetTokenAccount:
		wallet := strings.TrimSpace(classification.TokenOwnerWallet)
		if wallet == "" {
			return "", fmt.Errorf("token account owner wallet is unresolved")
		}
		return wallet, nil
	default:
		return "", fmt.Errorf("target type %s is not wallet-investigable", classification.Type)
	}
}

func (h *Handler) runCustomerWalletInvestigation(ctx context.Context, target, network string, classification radarTargetClassification) (customerWalletInvestigationResult, error) {
	out := customerWalletInvestigationResult{
		Target: target, Network: network, Classification: classification,
		FundingPersistence: "not_requested", RulePersistence: "not_requested",
	}
	wallet, err := resolveCustomerWalletTarget(target, classification)
	if err != nil {
		return out, err
	}
	out.Wallet = wallet

	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return out, fmt.Errorf("actor defense database is unavailable")
	}
	store := services.NewActorDefenseStore(db)
	initial, err := store.LoadPersistentWalletDossier(ctx, wallet, network, 75)
	if err != nil {
		return out, fmt.Errorf("assemble actor defense dossier: %w", err)
	}

	out.FundingOrigin, out.FundingPersistence = h.collectActorFundingOrigin(ctx, store, wallet, network)
	out.LiveCoverage = h.collectActorDefenseLiveEvidence(ctx, store, initial)
	if out.FundingPersistence == "failed" {
		out.LiveCoverage.PersistenceFailures++
		if out.LiveCoverage.Status == "complete" {
			out.LiveCoverage.Status = "partial_persistence"
		}
		out.LiveCoverage.Limitations = append(out.LiveCoverage.Limitations, "Funding-origin sonucu kalıcı actor index'e yazılamadı.")
	}

	out.Dossier, err = store.LoadPersistentWalletDossier(ctx, wallet, network, 100)
	if err != nil {
		return out, fmt.Errorf("refresh actor defense dossier: %w", err)
	}
	out.RuleVerdict = services.EvaluateActorDefenseRules(out.Dossier.Track, out.Dossier.Evidence)
	out.RulePersistence = "persisted"
	if err := store.PersistRuleVerdict(ctx, out.Dossier.Track, out.RuleVerdict); err != nil {
		out.RulePersistence = "failed"
		out.LiveCoverage.PersistenceFailures++
		if out.LiveCoverage.Status == "complete" {
			out.LiveCoverage.Status = "partial_persistence"
		}
		out.LiveCoverage.Limitations = append(out.LiveCoverage.Limitations, "Deterministik actor verdict kalıcı threat track'e yazılamadı.")
	}
	if out.Dossier.Coverage == nil {
		out.Dossier.Coverage = map[string]any{}
	}
	out.Dossier.Coverage["live_evidence"] = out.LiveCoverage
	out.Dossier.Coverage["funding_origin"] = out.FundingOrigin
	out.Dossier.Coverage["funding_origin_persistence"] = out.FundingPersistence
	out.Dossier.Coverage["requested_target"] = target
	out.Dossier.Coverage["resolved_wallet"] = wallet
	out.Dossier.Coverage["rule_verdict_persistence"] = out.RulePersistence
	out.Dossier.Coverage["numeric_score_disabled"] = true

	out.HasLiveEvidence = out.LiveCoverage.EvidencePersisted > 0 || out.FundingOrigin.ResultState == services.ActorFundingResultVerified
	out.HasPersistentEvidence = len(out.Dossier.Evidence) > 0
	out.PublishedResult = out.HasLiveEvidence || out.HasPersistentEvidence || out.FundingOrigin.ResultState == services.ActorFundingResultBounded
	return out, nil
}

func customerWalletInvestigationStatus(result customerWalletInvestigationResult) string {
	if result.PublishedResult {
		return "ready"
	}
	return "evidence_pending"
}

func customerWalletInvestigationMessage(result customerWalletInvestigationResult) string {
	if result.FundingOrigin.ResultState == services.ActorFundingResultBounded && !result.HasLiveEvidence && !result.HasPersistentEvidence {
		return "Wallet investigation reached its published chain boundary; no funding claim was emitted."
	}
	if result.PublishedResult {
		return "Wallet investigation completed with evidence-backed or explicitly bounded results."
	}
	return "Wallet investigation completed with evidence gaps; missing evidence is not treated as a safe finding."
}

func customerWalletInvestigationEnvelope(result customerWalletInvestigationResult, charged bool) map[string]any {
	return map[string]any{
		"ok":                      true,
		"status":                  customerWalletInvestigationStatus(result),
		"message":                 customerWalletInvestigationMessage(result),
		"investigation_kind":      "wallet_intelligence",
		"schema_version":          "koschei-wallet-intelligence-v1",
		"target":                  result.Target,
		"wallet":                  result.Wallet,
		"network":                 result.Network,
		"target_classification":   result.Classification,
		"has_live_evidence":       result.HasLiveEvidence,
		"has_persistent_evidence": result.HasPersistentEvidence,
		"published_result":        result.PublishedResult,
		"charged":                 charged,
		"dossier":                 result.Dossier,
		"funding_origin":          result.FundingOrigin,
		"actor_live_evidence":     result.LiveCoverage,
		"rule_verdict":            result.RuleVerdict,
		"evidence_policy": map[string]any{
			"numeric_final_score_disabled": true,
			"missing_evidence_is_not_safe": true,
			"bounded_is_not_verified":      true,
			"identity_scope":               "onchain_wallet_only",
		},
	}
}

func (h *Handler) securityRadarWalletCheck(w http.ResponseWriter, r *http.Request, authSubject, claimEmail, target, network string, classification radarTargetClassification) {
	services.WriteSecurityAuditEvent(r.Context(), h.DB, securityAuditFromRequest(r, "radar_wallet_check_requested", "customer", "info", map[string]any{
		"network": network, "target": target, "target_type": classification.Type,
	}))
	ctx, cancel := context.WithTimeout(r.Context(), 170*time.Second)
	defer cancel()
	result, err := h.runCustomerWalletInvestigation(ctx, target, network, classification)
	if err != nil {
		services.WriteSecurityAuditEvent(ctx, h.DB, securityAuditFromRequest(r, "radar_wallet_check_failed", "customer", "warning", map[string]any{
			"network": network, "target": target, "target_type": classification.Type,
		}))
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Wallet intelligence could not be assembled")
		return
	}

	charged := false
	if result.PublishedResult {
		if err := h.consumePremiumOutput(authSubject, claimEmail, "security_radar_wallet_check"); err != nil {
			writeJSON(w, http.StatusPaymentRequired, insufficientOutputsResponse())
			return
		}
		charged = true
	}
	status := customerWalletInvestigationStatus(result)
	if status == "evidence_pending" {
		services.WriteSecurityAuditEvent(ctx, h.DB, securityAuditFromRequest(r, "radar_wallet_check_evidence_pending", "customer", "warning", map[string]any{
			"network": network, "target": target, "wallet": result.Wallet,
		}))
	}
	h.logTool(claimEmail, "security_radar_wallet_check", status)
	h.trackEvent(claimEmail, "security_radar_wallet_check", r.URL.Path)
	writeJSON(w, http.StatusOK, customerWalletInvestigationEnvelope(result, charged))
}
