package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type actorDistributionRequest struct {
	CreatorWallet string `json:"creator_wallet"`
	Mint          string `json:"mint"`
	Network       string `json:"network"`
}

// OwnerActorDistributionInvestigation resolves the first observed creator
// recipients through mint-specific token-account history only. It never queries
// recipient-wide signature history.
func (h *Handler) OwnerActorDistributionInvestigation(w http.ResponseWriter, r *http.Request) {
	var input actorDistributionRequest
	if err := decodeJSON(r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Invalid request body")
		return
	}
	creator := strings.TrimSpace(input.CreatorWallet)
	mint := strings.TrimSpace(input.Mint)
	network := strings.TrimSpace(input.Network)
	if network == "" {
		network = "solana-mainnet"
	}
	if creator == "" || mint == "" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "creator_wallet and mint are required")
		return
	}
	if h.DB == nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Actor defense database is unavailable")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), time.Duration(actorDefenseEnvInt("ACTOR_RECIPIENT_TIMEOUT_SECONDS", 150, 30, 240))*time.Second)
	defer cancel()
	store := services.NewActorDefenseStore(h.DB)
	target, err := store.ResolvePersistentCreatorMint(ctx, creator, mint, network)
	if err != nil {
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok":             false,
			"error":          "creator_mint_relation_required",
			"message":        "Creator → mint ilişkisi kalıcı actor index içinde doğrulanmadan recipient araştırması başlatılmaz.",
			"creator_wallet": creator,
			"mint":           mint,
		})
		return
	}

	report := services.InvestigateActorInitialRecipients(ctx, creatorIntelRPCURL(), target.CreatorWallet, target.Mint, target.CreationSignature, services.ActorInitialRecipientOptions{
		MaxRecipients:        actorDefenseEnvInt("ACTOR_RECIPIENT_LIMIT", 20, 1, 20),
		SignaturePageSize:    actorDefenseEnvInt("ACTOR_RECIPIENT_SIGNATURE_PAGE_SIZE", 250, 50, 1000),
		MaxPagesPerTokenATA:  actorDefenseEnvInt("ACTOR_RECIPIENT_MAX_PAGES_PER_ATA", 8, 1, 20),
		MaxTransactionsParse: actorDefenseEnvInt("ACTOR_RECIPIENT_TRANSACTION_LIMIT", 160, 10, 500),
	})

	persisted := 0
	persistenceFailures := 0
	for _, evidence := range services.ActorInitialRecipientEvidence(report, network) {
		if err := store.UpsertEvidence(ctx, evidence); err != nil {
			persistenceFailures++
			continue
		}
		persisted++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":             true,
		"schema_version": "koschei-actor-distribution-v1",
		"network":        network,
		"target":         target,
		"report":         report,
		"persistence": map[string]any{
			"evidence_persisted": persisted,
			"failures":           persistenceFailures,
		},
		"policy": map[string]any{
			"recipient_full_wallet_history":        false,
			"mint_specific_ata_only":               true,
			"max_recipients":                       20,
			"bounded_history_never_called_initial": true,
		},
	})
}
