package handlers

import (
	"net/http"
	"strings"

	"koschei/api/internal/services"
)

func (h *Handler) WalletLinkageProbe(w http.ResponseWriter, r *http.Request) {
	walletA := strings.TrimSpace(r.URL.Query().Get("a"))
	walletB := strings.TrimSpace(r.URL.Query().Get("b"))
	if walletA == "" || walletB == "" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "a and b are required")
		return
	}

	network := strings.TrimSpace(r.URL.Query().Get("network"))
	if network == "" {
		network = "solana-mainnet"
	}

	options := services.ActorFundingOriginOptions{
		PageSize:                  100,
		MaxPages:                  10,
		OldestTransactionsToParse: 5,
	}
	originA, err := services.FindActorFundingOrigin(r.Context(), creatorIntelRPCURL(), walletA, options)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "wallet a funding origin could not be investigated")
		return
	}
	originB, err := services.FindActorFundingOrigin(r.Context(), creatorIntelRPCURL(), walletB, options)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "wallet b funding origin could not be investigated")
		return
	}

	sourceA := strings.TrimSpace(originA.SourceWallet)
	sourceB := strings.TrimSpace(originB.SourceWallet)
	relation := "no_funding_link_observed"
	verdict := "NO_LINK_OBSERVED"
	sharedSource := ""

	switch {
	case sourceA == walletB:
		relation = "b_funded_a"
		verdict = "VERIFIED_DIRECT_FUNDING_LINK"
	case sourceB == walletA:
		relation = "a_funded_b"
		verdict = "VERIFIED_DIRECT_FUNDING_LINK"
	case sourceA != "" && sourceA == sourceB:
		relation = "shared_funding_source"
		verdict = "SHARED_FUNDING_SOURCE_OBSERVED"
		sharedSource = sourceA
	}

	limitations := make([]string, 0, len(originA.Limitations)+len(originB.Limitations))
	limitations = append(limitations, originA.Limitations...)
	limitations = append(limitations, originB.Limitations...)

	writeJSON(w, http.StatusOK, map[string]any{
		"wallet_a":       walletA,
		"wallet_b":       walletB,
		"network":        network,
		"relation":       relation,
		"verdict":        verdict,
		"funding_a":      originA,
		"funding_b":      originB,
		"shared_source":  sharedSource,
		"identity_scope": "onchain_wallet_only",
		"disclaimers": []string{
			"Ortak fonlama kaynağı bir borsa, servis veya köprü cüzdanı olabilir; tek başına ortak sahiplik kanıtı değildir.",
			"Bu sonuç gerçek kişi kimliği veya kötü niyet iddiası içermez.",
			"Funding taraması sınırlı imza penceresi kullanır; bağ görülmemesi bağ olmadığını kanıtlamaz.",
		},
		"limitations": limitations,
	})
}
