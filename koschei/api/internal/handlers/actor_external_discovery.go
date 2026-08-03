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
			Status: "rpc_only", Provider: "helius_solana_rpc", Wallet: wallet,
			Limitations: []string{},
		},
		CreatedMintPortfolio: newActorCreatedMintIntegrationRun(wallet),
		Limitations:          []string{},
	}
}

func (h *Handler) collectActorExternalDiscovery(ctx context.Context, store *services.ActorDefenseStore, wallet, network string) actorExternalDiscoveryRun {
	wallet = strings.TrimSpace(wallet)
	out := newActorExternalDiscoveryRun(wallet)
	if wallet == "" {
		out.Status = "wallet_required"
		out.Limitations = append(out.Limitations, "Actor discovery için wallet hedefi çözümlenemedi.")
		return out
	}

	out.CreatedMintPortfolio = h.collectActorCreatedMintPortfolio(ctx, store, wallet, network)
	out.Limitations = append(out.Limitations, out.CreatedMintPortfolio.Limitations...)
	out.Discovery.Configured = out.CreatedMintPortfolio.Discovery.Configured
	out.Discovery.Available = out.CreatedMintPortfolio.Discovery.Available
	out.Discovery.Status = out.CreatedMintPortfolio.Discovery.Status
	out.Discovery.Provider = out.CreatedMintPortfolio.Discovery.Provider
	out.Discovery.Limitations = append(out.Discovery.Limitations, out.CreatedMintPortfolio.Discovery.Limitations...)

	if out.CreatedMintPortfolio.Discovery.Available {
		out.Status = "created_mint_portfolio_helius"
	} else {
		out.Status = "no_external_discovery"
	}
	return out
}
