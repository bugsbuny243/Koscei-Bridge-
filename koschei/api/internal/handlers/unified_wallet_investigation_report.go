package handlers

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"koschei/api/internal/services"
)

// buildUnifiedWalletInvestigationReport is the caller-neutral wallet-first
// technical engine. Owner, customer job and recursive actor paths consume the
// same report; caller-specific metadata is added by the route/worker wrapper.
func (h *Handler) buildUnifiedWalletInvestigationReport(ctx context.Context, requestedTarget, wallet, network string, liveEvidence bool) (map[string]any, error) {
	requestedTarget = strings.TrimSpace(requestedTarget)
	wallet = strings.TrimSpace(wallet)
	network = strings.TrimSpace(network)
	if network == "" {
		network = "solana-mainnet"
	}
	if wallet == "" {
		return nil, errors.New("wallet target is required")
	}
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return nil, errors.New("wallet investigation database is unavailable")
	}
	store := services.NewActorDefenseStore(db)
	initial, err := store.LoadPersistentWalletDossier(ctx, wallet, network, 150)
	if err != nil {
		return nil, err
	}
	coverage := actorDefenseLiveCoverage{Status: "stored_evidence_only", Limitations: []string{}}
	funding := services.ActorFundingOrigin{
		Wallet: wallet, Status: "stored_evidence_only", VerificationStatus: "unverified",
		TrailStatus: "not_investigated", IdentityScope: "onchain_wallet_only", Limitations: []string{},
	}
	fundingPersistence := "not_requested"
	externalDiscovery := newActorExternalDiscoveryRun(wallet)
	working := initial
	if liveEvidence {
		externalDiscovery = h.collectActorExternalDiscovery(ctx, store, wallet, network)
		funding, fundingPersistence = h.collectActorFundingOrigin(ctx, store, wallet, network)
		if refreshed, refreshErr := store.LoadPersistentWalletDossier(ctx, wallet, network, 250); refreshErr == nil {
			working = refreshed
		}
		coverage = h.collectActorDefenseLiveEvidence(ctx, store, working)
	}
	final, err := store.LoadPersistentWalletDossier(ctx, wallet, network, 300)
	if err != nil {
		return nil, err
	}
	actorVerdict := services.EvaluateActorDefenseRules(final.Track, final.Evidence)
	actorVerdictPersistence := "persisted"
	if err := store.PersistRuleVerdict(ctx, final.Track, actorVerdict); err != nil {
		actorVerdictPersistence = "failed"
	}
	acceptance := services.EvaluateActorAcceptance(services.ActorAcceptanceInput{
		Wallet: wallet, Network: network, TargetKind: "wallet", Dossier: final,
		FundingOrigin: funding, Verdict: actorVerdict,
	})
	now := time.Now().UTC()
	behavior := services.EvaluateUnifiedRadarBehavior(
		"", wallet, services.TokenMarketSnapshot{}, services.HolderIntelligence{},
		services.HolderClusterAnalysis{}, services.CreatorSellAcceleration{}, now,
	)
	unifiedVerdict := services.EvaluateUnifiedRadarVerdict(wallet, actorVerdict, behavior)
	unifiedPersistence, unifiedHistory := h.persistUnifiedRadarVerdict(ctx, db, network, "wallet", wallet, unifiedVerdict, behavior)
	evidenceGraph := services.BuildActorEvidenceGraph(final)
	report := map[string]any{
		"ok": true,
		"schema_version": "koschei-unified-wallet-investigation-v1",
		"target": requestedTarget,
		"wallet": wallet,
		"network": network,
		"generated_at": now.Format(time.RFC3339),
		"analysis_scope": "wallet_actor_investigation",
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
		"legacy_14_arm_radar": map[string]any{
			"applicable": false,
			"reason": "Token-specific collectors are not fabricated for a wallet-only target.",
			"modules": []any{},
		},
		"actor_investigation": map[string]any{
			"wallet": wallet,
			"dossier": final,
			"external_discovery": externalDiscovery,
			"funding_origin": funding,
			"funding_origin_persistence": fundingPersistence,
			"actor_live_evidence": coverage,
			"live_evidence": coverage,
			"evidence_graph": evidenceGraph,
			"rule_verdict": actorVerdict,
			"rule_verdict_persistence": actorVerdictPersistence,
		},
		"behavior_signals": behavior,
		"investigation_output_policy": services.SharedInvestigationOutputPolicy(),
		"evidence_policy": map[string]any{
			"numeric_final_score_disabled": true,
			"numeric_rug_probability_disabled": true,
			"no_evidence_no_claim": true,
			"inferred_watch_only": true,
			"unverified_excluded": true,
			"external_attribution_is_observed_only": true,
			"identity_scope": "onchain_wallet_only",
			"caller_type_changes_evidence": false,
		},
	}
	attachCanonicalWalletIntegrationCoverage(report)
	_ = h.persistDossierSourceSnapshot(ctx, report)
	return report, nil
}

func attachCanonicalWalletIntegrationCoverage(report map[string]any) {
	actor := canonicalMap(report["actor_investigation"])
	live := canonicalLiveScanRequested(report)
	capabilities := map[string]canonicalCapabilityStatus{}
	put := func(key string, status canonicalCapabilityStatus) {
		if status.Limitations == nil {
			status.Limitations = []string{}
		}
		capabilities[key] = status
	}
	put("solscan_actor_discovery", canonicalStatusFromRaw("Solscan actor discovery and attribution", actor["external_discovery"], live, true, "actor_investigation.external_discovery"))
	external := canonicalMap(actor["external_discovery"])
	put("created_mint_portfolio", canonicalStatusFromRaw("Created-mint portfolio discovery and RPC verification", external["created_mint_portfolio"], live, true, "actor_investigation.external_discovery.created_mint_portfolio"))
	put("funding_origin", canonicalStatusFromRaw("Actor funding origin", actor["funding_origin"], live, true, "actor_investigation.funding_origin"))
	put("actor_live_transaction_evidence", canonicalStatusFromRaw("Actor live transaction evidence", actor["actor_live_evidence"], live, true, "actor_investigation.actor_live_evidence"))
	put("persistent_actor_dossier", canonicalStatusFromDossier(actor["dossier"], live))
	put("actor_evidence_graph", canonicalStatusFromGraph(actor["evidence_graph"], live))
	put("actor_ruleset", canonicalStatusFromSignedVerdict("Deterministic actor ruleset", actor["rule_verdict"], true, "actor_investigation.rule_verdict"))
	put("deterministic_unified_verdict", canonicalStatusFromSignedVerdict("Deterministic Unified Verdict", report["final_verdict"], true, "final_verdict"))

	coverage := canonicalIntegrationCoverage{
		SchemaVersion: "koschei-wallet-capability-integration-v1",
		OverallStatus: "complete",
		LiveScanRequested: live,
		Capabilities: capabilities,
		OrphanCapabilities: []string{},
		Policy: map[string]any{
			"wallet_target_does_not_fabricate_token_collectors": true,
			"feature_without_trigger_is_orphan": true,
			"full_scan_cannot_claim_complete_when_required_capability_is_unavailable": true,
		},
	}
	for key, item := range capabilities {
		if !item.WiredToCanonicalRadar {
			coverage.OrphanCapabilityCount++
			coverage.OrphanCapabilities = append(coverage.OrphanCapabilities, key)
		}
		if !item.RequiredForFullScan {
			continue
		}
		coverage.RequiredCapabilityCount++
		switch item.Status {
		case canonicalCapabilityActive:
			coverage.ActiveRequiredCount++
		case canonicalCapabilityPartial:
			coverage.PartialRequiredCount++
		case canonicalCapabilityNotRequested:
			coverage.NotRequestedRequiredCount++
		default:
			coverage.UnavailableRequiredCount++
		}
	}
	if !live {
		coverage.OverallStatus = "stored_or_preflight_projection"
	} else if coverage.UnavailableRequiredCount > 0 || coverage.OrphanCapabilityCount > 0 {
		coverage.OverallStatus = "blocked"
	} else if coverage.PartialRequiredCount > 0 || coverage.NotRequestedRequiredCount > 0 {
		coverage.OverallStatus = "partial"
	}
	report["capability_integration"] = coverage
}

func canonicalWalletDB(h *Handler) *sql.DB {
	if h == nil {
		return nil
	}
	if h.DBRead != nil {
		return h.DBRead
	}
	return h.DB
}
