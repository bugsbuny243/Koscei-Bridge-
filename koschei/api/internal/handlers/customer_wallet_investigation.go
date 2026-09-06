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
	ExternalDiscovery     actorExternalDiscoveryRun
	FundingOrigin         services.ActorFundingOrigin
	FundingPersistence    string
	LiveCoverage          actorDefenseLiveCoverage
	RuleVerdict           services.ActorDefenseRuleVerdict
	RulePersistence       string
	HasLiveEvidence       bool
	HasPersistentEvidence bool
	PublishedResult       bool
	ExecutionMode         string
	Memory                intelligenceMemoryReceipt
	HistoricalMemory      intelligenceMemoryReadReceipt
}

func radarTargetWalletInvestigationAllowed(classification radarTargetClassification) bool {
	if classification.Type == radarTargetWallet || classification.Type == radarTargetProgram || classification.Type == radarTargetTransactionSignature {
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
		ExecutionMode: "persistent_legacy",
	}
	wallet, err := resolveCustomerWalletTarget(target, classification)
	if err != nil {
		return out, err
	}
	out.Wallet = wallet
	// Historical Drive memory is contextual only and is loaded before live
	// collection so the snapshot written by this run cannot be misreported as
	// prior history. Fresh chain evidence always takes precedence.
	out.HistoricalMemory = h.loadLatestIntelligenceMemory(ctx, "wallet_investigation", network, wallet)

	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return h.runCustomerWalletInvestigationStateless(ctx, out), nil
	}
	store := services.NewActorDefenseStore(db)
	initial, err := store.LoadPersistentWalletDossier(ctx, wallet, network, 75)
	if err != nil {
		return out, fmt.Errorf("assemble actor defense dossier: %w", err)
	}

	out.ExternalDiscovery = newActorExternalDiscoveryRun(wallet)
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

func (h *Handler) runCustomerWalletInvestigationStateless(ctx context.Context, out customerWalletInvestigationResult) customerWalletInvestigationResult {
	now := time.Now().UTC()
	wallet := out.Wallet
	network := out.Network
	out.ExecutionMode = "stateless_live"
	out.FundingPersistence = "drive_first_request_scoped"
	out.RulePersistence = "drive_first_request_scoped"
	out.HasPersistentEvidence = false
	out.Dossier = services.ActorDefenseDossier{
		Wallet:        wallet,
		Network:       network,
		Tokens:        []services.ActorDefenseTokenObservation{},
		RelatedActors: []services.ActorDefenseRelatedActor{},
		Evidence:      []services.ActorDefenseEvidenceRecord{},
		Coverage:      map[string]any{},
		Policy: map[string]any{
			"no_evidence_no_claim":                                           true,
			"wallet_addresses_are_case_sensitive":                            true,
			"verified_requires_transaction_or_owner_resolved_chain_evidence": true,
			"identity_or_wrongdoing_claim":                                   false,
			"durable_intelligence_backend":                                   "google_drive",
			"neon_intelligence_persistence":                                  false,
		},
		GeneratedAt: now,
	}
	out.Dossier.Track = services.ActorDefenseTrack{
		Network:    network,
		TargetKind: "wallet",
		TargetID:   wallet,
		State:      "detected",
		Dossier: map[string]any{
			"state_basis":                 []string{"live_rpc_evidence", "bounded_created_mint_discovery"},
			"persistence":                 "drive_first_request_scoped",
			"no_identity_or_intent_claim": true,
		},
	}

	out.ExternalDiscovery = h.collectActorExternalDiscovery(ctx, nil, wallet, network)
	for _, candidate := range out.ExternalDiscovery.CreatedMintPortfolio.VerifiedCandidates {
		if strings.TrimSpace(candidate.Mint) == "" {
			continue
		}
		out.Dossier.Tokens = append(out.Dossier.Tokens, services.ActorDefenseTokenObservation{
			Mint:             candidate.Mint,
			Roles:            []string{"creator"},
			CreatorSignature: candidate.Signature,
			FirstObservedAt:  candidate.ObservedAt,
			LastObservedAt:   candidate.ObservedAt,
		})
	}
	out.Dossier.Track.CreatedTokenCount = len(out.Dossier.Tokens)
	out.Dossier.Evidence = append(out.Dossier.Evidence, services.ActorCreatedMintCandidateEvidence(wallet, network, out.ExternalDiscovery.CreatedMintPortfolio.VerifiedCandidates)...)

	out.FundingOrigin, _ = h.collectActorFundingOrigin(ctx, nil, wallet, network)
	if fundingEvidence, ok := services.ActorFundingOriginEvidence(out.FundingOrigin, network); ok {
		out.Dossier.Evidence = append(out.Dossier.Evidence, fundingEvidence)
	}
	out.LiveCoverage = h.collectActorDefenseLiveEvidence(ctx, nil, out.Dossier)
	out.Dossier.Evidence = append(out.Dossier.Evidence, out.LiveCoverage.Evidence...)

	verified, observed := 0, 0
	for _, item := range out.Dossier.Evidence {
		switch strings.ToLower(strings.TrimSpace(item.VerificationStatus)) {
		case "verified":
			verified++
		case "observed":
			observed++
		}
	}
	out.Dossier.Track.VerifiedEvidenceCount = verified
	out.Dossier.Track.ObservedEvidenceCount = observed
	out.Dossier.Track.State = services.DeriveActorDefenseTrackState(out.Dossier.Track, out.Dossier.RelatedActors)
	out.Dossier.Track.Dossier["token_count"] = len(out.Dossier.Tokens)
	out.Dossier.Track.Dossier["direct_evidence_count"] = len(out.Dossier.Evidence)
	out.Dossier.Coverage["live_evidence"] = out.LiveCoverage
	out.Dossier.Coverage["funding_origin"] = out.FundingOrigin
	out.Dossier.Coverage["external_discovery"] = out.ExternalDiscovery
	out.Dossier.Coverage["persistence"] = "drive_first_request_scoped"
	out.Dossier.Coverage["numeric_score_disabled"] = true

	out.RuleVerdict = services.EvaluateActorDefenseRules(out.Dossier.Track, out.Dossier.Evidence)
	out.HasLiveEvidence = len(out.Dossier.Evidence) > 0 || out.ExternalDiscovery.AddressHistory.SignaturesSeen > 0 || out.FundingOrigin.ResultState == services.ActorFundingResultVerified
	out.PublishedResult = out.HasLiveEvidence || out.FundingOrigin.ResultState == services.ActorFundingResultBounded

	memoryPayload := map[string]any{
		"schema_version":        "koschei-wallet-intelligence-v1",
		"target":                out.Target,
		"wallet":                wallet,
		"network":               network,
		"target_classification": out.Classification,
		"dossier":               out.Dossier,
		"external_discovery":    out.ExternalDiscovery,
		"funding_origin":        out.FundingOrigin,
		"actor_live_evidence":   out.LiveCoverage,
		"rule_verdict":          out.RuleVerdict,
	}
	out.Memory = h.archiveIntelligenceMemory(ctx, "wallet_investigation", network, wallet, memoryPayload)
	return out
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
		"execution_mode":          result.ExecutionMode,
		"has_live_evidence":       result.HasLiveEvidence,
		"has_persistent_evidence": result.HasPersistentEvidence,
		"published_result":        result.PublishedResult,
		"charged":                 charged,
		"dossier":                 result.Dossier,
		"external_discovery":      result.ExternalDiscovery,
		"funding_origin":          result.FundingOrigin,
		"actor_live_evidence":     result.LiveCoverage,
		"rule_verdict":            result.RuleVerdict,
		"historical_memory":       result.HistoricalMemory,
		"intelligence_memory":     result.Memory,
		"evidence_policy": map[string]any{
			"numeric_final_score_disabled":                  true,
			"missing_evidence_is_not_safe":                  true,
			"bounded_is_not_verified":                       true,
			"identity_scope":                                "onchain_wallet_only",
			"historical_memory_cannot_override_live_evidence": true,
			"historical_snapshot_is_not_current_chain_state":  true,
			"neon_intelligence_persistence":                 false,
			"durable_memory_backend":                        "google_drive",
		},
	}
}

func (h *Handler) securityRadarWalletCheck(w http.ResponseWriter, r *http.Request, authSubject, claimEmail, target, network string, classification radarTargetClassification) {
	if classification.Type == radarTargetTransactionSignature {
		h.securityRadarTransactionCheck(w, r, authSubject, claimEmail, target, network, classification)
		return
	}
	if classification.Type == radarTargetProgram {
		h.securityRadarProgramCheck(w, r, authSubject, claimEmail, target, network, classification)
		return
	}

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
