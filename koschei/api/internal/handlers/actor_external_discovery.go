package handlers

import (
	"context"
	"strings"

	"koschei/api/internal/services"
)

type actorProviderDiscovery struct {
	Configured  bool     `json:"configured"`
	Available   bool     `json:"available"`
	Status      string   `json:"status"`
	Provider    string   `json:"provider"`
	Wallet      string   `json:"wallet"`
	Limitations []string `json:"limitations"`
}

type actorExternalDiscoveryRun struct {
	Status                    string                            `json:"status"`
	Discovery                 actorProviderDiscovery            `json:"discovery"`
	AddressHistory            services.AddressHistoryReport     `json:"address_history"`
	AddressFlow               addressFlowReport                 `json:"address_flow"`
	AddressAttribution        addressAttributionReport          `json:"address_attribution"`
	AddressInteractions       addressInteractionsReport         `json:"address_interactions"`
	FundingPaths              addressFundingPathsReport         `json:"funding_paths"`
	MultiHopFundingPaths      addressMultiHopFundingPathsReport `json:"multi_hop_funding_paths"`
	AddressRelationships      addressRelationshipsReport        `json:"address_relationships"`
	BehaviorTimeline          addressBehaviorTimelineReport     `json:"behavior_timeline"`
	BehaviorPatterns          addressBehaviorPatternsReport     `json:"behavior_patterns"`
	BehaviorSummary           addressBehaviorSummaryReport      `json:"behavior_summary"`
	CreatedMintPortfolio      actorCreatedMintIntegrationRun    `json:"created_mint_portfolio"`
	CreatorOutcomeHistory     creatorOutcomeHistoryReport       `json:"creator_outcome_history"`
	CreatorTokenObservedPaths creatorTokenObservedPathsReport   `json:"creator_token_observed_paths"`
	EvidenceProduced          int                               `json:"evidence_produced"`
	EvidencePersisted         int                               `json:"evidence_persisted"`
	PersistenceFailures       int                               `json:"persistence_failures"`
	IntelligenceMemory        intelligenceMemoryReceipt         `json:"intelligence_memory"`
	Limitations               []string                          `json:"limitations"`
}

func newActorExternalDiscoveryRun(wallet string) actorExternalDiscoveryRun {
	wallet = strings.TrimSpace(wallet)
	return actorExternalDiscoveryRun{
		Status: "not_requested",
		Discovery: actorProviderDiscovery{
			Status: "rpc_only", Provider: "solana_rpc", Wallet: wallet,
			Limitations: []string{},
		},
		AddressHistory: services.AddressHistoryReport{
			SchemaVersion: "koschei-address-history-v1", Status: "not_requested",
			Address: wallet, Entries: []services.AddressHistoryEntry{}, Limitations: []string{},
			EvidenceSource: "solana_getSignaturesForAddress", IdentityScope: "onchain_address_only",
		},
		AddressFlow:               newAddressFlowReport(wallet, "solana-mainnet"),
		AddressAttribution:        newAddressAttributionReport(wallet),
		AddressInteractions:       newAddressInteractionsReport(wallet),
		FundingPaths:              newAddressFundingPathsReport(wallet),
		MultiHopFundingPaths:      newAddressMultiHopFundingPathsReport(wallet),
		AddressRelationships:      buildAddressRelationships(wallet, newAddressFlowReport(wallet, "solana-mainnet"), newAddressAttributionReport(wallet)),
		BehaviorTimeline:          newAddressBehaviorTimelineReport(wallet),
		BehaviorPatterns:          newAddressBehaviorPatternsReport(wallet),
		BehaviorSummary:           newAddressBehaviorSummaryReport(wallet),
		CreatedMintPortfolio:      newActorCreatedMintIntegrationRun(wallet),
		CreatorOutcomeHistory:     newCreatorOutcomeHistoryReport(wallet),
		CreatorTokenObservedPaths: newCreatorTokenObservedPathsReport(wallet),
		IntelligenceMemory:        intelligenceMemoryReceipt{Status: "not_requested"},
		Limitations:               []string{},
	}
}

func (h *Handler) collectActorExternalDiscovery(ctx context.Context, store *services.ActorDefenseStore, wallet, network string) actorExternalDiscoveryRun {
	wallet = strings.TrimSpace(wallet)
	out := newActorExternalDiscoveryRun(wallet)
	out.AddressFlow.Network = network
	if wallet == "" {
		out.Status = "wallet_required"
		out.Limitations = append(out.Limitations, "Actor discovery için wallet hedefi çözümlenemedi.")
		return out
	}

	history, historyErr := services.CollectAddressHistory(ctx, creatorIntelRPCURL(), network, wallet, services.AddressHistoryOptions{
		PageSize: actorDefenseEnvInt("ARVIS_ADDRESS_HISTORY_PAGE_SIZE", 250, 50, 1000),
		MaxPages: actorDefenseEnvInt("ARVIS_ADDRESS_HISTORY_MAX_PAGES", 8, 1, 20),
	})
	out.AddressHistory = history
	if historyErr != nil {
		out.Limitations = append(out.Limitations, "Address history collection incomplete: "+creatorIntelCompactError(historyErr))
	}
	out.Limitations = append(out.Limitations, history.Limitations...)

	out.AddressFlow = h.collectAddressFlow(ctx, wallet, network, history)
	out.Limitations = append(out.Limitations, out.AddressFlow.Limitations...)
	out.AddressAttribution = collectAddressAttribution(ctx, wallet, creatorIntelRPCURL(), out.AddressFlow)
	out.Limitations = append(out.Limitations, out.AddressAttribution.Limitations...)
	out.AddressInteractions = buildAddressInteractions(wallet, out.AddressFlow, out.AddressAttribution)
	out.Limitations = append(out.Limitations, out.AddressInteractions.Limitations...)
	out.FundingPaths = buildAddressFundingPaths(wallet, out.AddressFlow, out.AddressAttribution)
	out.Limitations = append(out.Limitations, out.FundingPaths.Limitations...)
	out.MultiHopFundingPaths = h.collectAddressMultiHopFundingPaths(ctx, wallet, network, out.FundingPaths)
	out.Limitations = append(out.Limitations, out.MultiHopFundingPaths.Limitations...)
	out.AddressRelationships = buildAddressRelationships(wallet, out.AddressFlow, out.AddressAttribution)
	out.Limitations = append(out.Limitations, out.AddressRelationships.Limitations...)

	out.CreatedMintPortfolio = h.collectActorCreatedMintPortfolio(ctx, store, wallet, network)
	out.Limitations = append(out.Limitations, out.CreatedMintPortfolio.Limitations...)
	out.CreatorOutcomeHistory = buildCreatorOutcomeHistory(wallet, out.CreatedMintPortfolio)
	out.Limitations = append(out.Limitations, out.CreatorOutcomeHistory.Limitations...)
	out.CreatorTokenObservedPaths = buildCreatorTokenObservedPaths(wallet, out.CreatedMintPortfolio, out.AddressFlow, out.AddressInteractions, out.CreatorOutcomeHistory)
	out.Limitations = append(out.Limitations, out.CreatorTokenObservedPaths.Limitations...)
	out.BehaviorTimeline = buildAddressBehaviorTimeline(wallet, out.AddressFlow, out.CreatedMintPortfolio)
	out.Limitations = append(out.Limitations, out.BehaviorTimeline.Limitations...)
	out.BehaviorPatterns = buildAddressBehaviorPatterns(wallet, out.AddressFlow, out.AddressRelationships, out.BehaviorTimeline)
	out.Limitations = append(out.Limitations, out.BehaviorPatterns.Limitations...)
	out.BehaviorSummary = buildAddressBehaviorSummary(wallet, history.HistoryComplete, out.AddressFlow, out.AddressRelationships, out.BehaviorTimeline, out.BehaviorPatterns)
	out.Limitations = append(out.Limitations, out.BehaviorSummary.Limitations...)
	out.Discovery.Configured = out.CreatedMintPortfolio.Discovery.Configured || history.Status != "rpc_unavailable"
	out.Discovery.Available = out.CreatedMintPortfolio.Discovery.Available || history.SignaturesSeen > 0 || history.HistoryComplete
	out.Discovery.Status = out.CreatedMintPortfolio.Discovery.Status
	out.Discovery.Provider = out.CreatedMintPortfolio.Discovery.Provider
	out.Discovery.Limitations = append(out.Discovery.Limitations, out.CreatedMintPortfolio.Discovery.Limitations...)

	switch {
	case out.BehaviorSummary.Status == "observed_behavior_summary_available" && out.BehaviorPatterns.TriggeredCount > 0 && out.BehaviorTimeline.EventCount > 0 && out.AddressRelationships.RelationshipCount > 0 && out.AddressAttribution.ResolvedCount > 0 && history.HistoryComplete && out.AddressFlow.FlowComplete:
		out.Status = "address_intelligence_summary_complete_for_observed_evidence"
	case out.BehaviorSummary.Status == "observed_behavior_summary_available":
		out.Status = "address_behavior_summary_available_with_gaps"
	case out.MultiHopFundingPaths.ExtensionsObserved > 0 && out.AddressAttribution.ResolvedCount > 0:
		out.Status = "address_history_flow_verified_multihop_paths_and_attribution_available"
	case out.MultiHopFundingPaths.ExtensionsObserved > 0:
		out.Status = "address_history_flow_and_multihop_paths_available"
	case out.FundingPaths.PathCandidateCount > 0 && out.AddressRelationships.RelationshipCount > 0 && out.AddressAttribution.ResolvedCount > 0 && history.HistoryComplete && out.AddressFlow.FlowComplete:
		out.Status = "address_history_flow_funding_paths_relationships_and_verified_attribution_available"
	case out.FundingPaths.PathCandidateCount > 0 && history.SignaturesSeen > 0:
		out.Status = "address_history_flow_and_funding_paths_available"
	case out.BehaviorPatterns.TriggeredCount > 0 && out.BehaviorTimeline.EventCount > 0 && out.AddressRelationships.RelationshipCount > 0 && out.AddressAttribution.ResolvedCount > 0 && history.HistoryComplete && out.AddressFlow.FlowComplete:
		out.Status = "address_history_flow_relationships_attribution_timeline_and_patterns_available"
	case out.BehaviorPatterns.TriggeredCount > 0 && out.BehaviorTimeline.EventCount > 0:
		out.Status = "address_history_flow_timeline_and_patterns_available"
	case out.BehaviorTimeline.EventCount > 0 && out.AddressRelationships.RelationshipCount > 0 && out.AddressAttribution.ResolvedCount > 0 && history.HistoryComplete && out.AddressFlow.FlowComplete:
		out.Status = "address_history_flow_relationships_attribution_and_timeline_available"
	case out.BehaviorTimeline.EventCount > 0 && out.AddressRelationships.RelationshipCount > 0:
		out.Status = "address_history_flow_relationships_and_timeline_available"
	case out.AddressRelationships.RelationshipCount > 0 && out.AddressAttribution.ResolvedCount > 0 && history.HistoryComplete && out.AddressFlow.FlowComplete:
		out.Status = "address_history_flow_relationships_and_verified_attribution_available"
	case out.AddressRelationships.RelationshipCount > 0 && history.SignaturesSeen > 0:
		out.Status = "address_history_flow_and_relationships_available"
	case out.AddressAttribution.ResolvedCount > 0 && history.HistoryComplete && out.AddressFlow.FlowComplete:
		out.Status = "address_history_flow_and_verified_attribution_available"
	case history.HistoryComplete && out.AddressFlow.FlowComplete && out.CreatedMintPortfolio.Discovery.Available:
		out.Status = "address_history_flow_and_created_mint_portfolio_available"
	case history.SignaturesSeen > 0 && out.AddressFlow.TransactionsDecoded > 0:
		out.Status = "address_history_and_flow_available"
	case history.HistoryComplete && out.CreatedMintPortfolio.Discovery.Available:
		out.Status = "address_history_and_created_mint_portfolio_available"
	case history.SignaturesSeen > 0 || history.HistoryComplete:
		out.Status = "address_history_available"
	case out.CreatedMintPortfolio.Discovery.Available:
		out.Status = "created_mint_portfolio_available"
	default:
		out.Status = "no_external_discovery"
	}

	// Archive the complete evidence projection after all derived address layers
	// have been assembled. The receipt is added afterwards, so the archived
	// payload is stable and does not recursively contain its own Drive object.
	out.IntelligenceMemory = h.archiveIntelligenceMemory(ctx, "wallet_address_investigation", network, wallet, out)
	return out
}
