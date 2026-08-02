package handlers

import (
	"context"
	"strings"

	"koschei/api/internal/services"
)

type actorExternalDiscoveryRun struct {
	Status               string                         `json:"status"`
	Discovery            services.SolscanActorDiscovery `json:"discovery"`
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
		Discovery: services.SolscanActorDiscovery{
			Status: "rpc_only", Provider: "helius_solana_rpc", Wallet: wallet,
			TransactionCandidates: []services.SolscanAccountTransaction{},
			TokenAccounts:         []services.SolscanTokenAccountObservation{},
			EndpointStatus:        map[string]string{}, Limitations: []string{},
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

	// Solscan actor discovery devre dışı bırakıldı: Pro API key 401 veriyor
	// ve created-mint portföyü zaten Helius üzerinden toplanıyor. Solscan'e
	// bağımlılık kaldırıldı.
	if out.CreatedMintPortfolio.Discovery.Available {
		out.Status = "created_mint_portfolio_helius"
	} else {
		out.Status = "no_external_discovery"
	}
	return out
}
