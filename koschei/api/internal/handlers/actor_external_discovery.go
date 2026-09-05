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
	Status               string                         `json:"status"`
	Discovery            actorProviderDiscovery         `json:"discovery"`
	AddressHistory       services.AddressHistoryReport  `json:"address_history"`
	AddressFlow          addressFlowReport              `json:"address_flow"`
	AddressAttribution   addressAttributionReport       `json:"address_attribution"`
	CreatedMintPortfolio actorCreatedMintIntegrationRun `json:"created_mint_portfolio"`
	EvidenceProduced     int                            `json:"evidence_produced"`
	EvidencePersisted    int                            `json:"evidence_persisted"`
	PersistenceFailures  int                            `json:"persistence_failures"`
	Limitations          []string                       `json:"limitations"`
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
		AddressFlow:          newAddressFlowReport(wallet, "solana-mainnet"),
		AddressAttribution:   newAddressAttributionReport(wallet),
		CreatedMintPortfolio: newActorCreatedMintIntegrationRun(wallet),
		Limitations:          []string{},
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

	out.CreatedMintPortfolio = h.collectActorCreatedMintPortfolio(ctx, store, wallet, network)
	out.Limitations = append(out.Limitations, out.CreatedMintPortfolio.Limitations...)
	out.Discovery.Configured = out.CreatedMintPortfolio.Discovery.Configured || history.Status != "rpc_unavailable"
	out.Discovery.Available = out.CreatedMintPortfolio.Discovery.Available || history.SignaturesSeen > 0 || history.HistoryComplete
	out.Discovery.Status = out.CreatedMintPortfolio.Discovery.Status
	out.Discovery.Provider = out.CreatedMintPortfolio.Discovery.Provider
	out.Discovery.Limitations = append(out.Discovery.Limitations, out.CreatedMintPortfolio.Discovery.Limitations...)

	switch {
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
	return out
}
