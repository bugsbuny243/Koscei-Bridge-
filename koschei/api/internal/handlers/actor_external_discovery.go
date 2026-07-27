package handlers

import (
	"context"
	"strings"

	"koschei/api/internal/services"
)

type actorExternalDiscoveryRun struct {
	Status               string                          `json:"status"`
	Discovery            services.SolscanActorDiscovery `json:"discovery"`
	CreatedMintPortfolio actorCreatedMintIntegrationRun `json:"created_mint_portfolio"`
	EvidenceProduced     int                             `json:"evidence_produced"`
	EvidencePersisted    int                             `json:"evidence_persisted"`
	PersistenceFailures  int                             `json:"persistence_failures"`
	Limitations          []string                        `json:"limitations"`
}

func newActorExternalDiscoveryRun(wallet string) actorExternalDiscoveryRun {
	wallet = strings.TrimSpace(wallet)
	return actorExternalDiscoveryRun{
		Status: "not_requested",
		Discovery: services.SolscanActorDiscovery{
			Status: "rpc_only", Provider: "helius_solana_rpc", Wallet: wallet,
			TransactionCandidates: []services.SolscanAccountTransaction{},
			TokenAccounts: []services.SolscanTokenAccountObservation{},
			EndpointStatus: map[string]string{}, Limitations: []string{},
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

	// Creator-mint candidates come from Helius enhanced transactions and are
	// independently verified through canonical Solana RPC. Solscan actor
	// metadata, transaction and token-account endpoints are intentionally not
	// called because the Pro endpoint returned 401 and poisoned the report.
	out.CreatedMintPortfolio = h.collectActorCreatedMintPortfolio(ctx, store, wallet, network)
	out.Limitations = append(out.Limitations, out.CreatedMintPortfolio.Limitations...)
	out.Discovery.Configured = strings.TrimSpace(creatorIntelRPCURL()) != ""
	out.Discovery.Available = out.CreatedMintPortfolio.Discovery.Available
	out.Discovery.EndpointStatus["created_mint_portfolio"] = out.CreatedMintPortfolio.Status
	out.Status = out.CreatedMintPortfolio.Status
	return out
}
