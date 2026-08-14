package handlers

import (
	"context"
	"strings"

	"koschei/api/internal/services"
)

func (h *Handler) collectActorFundingOriginForToken(ctx context.Context, store *services.ActorDefenseStore, wallet, network, tokenMint string) (services.ActorFundingOrigin, string) {
	origin, persistence := h.collectActorFundingOrigin(ctx, store, wallet, network)
	tokenMint = strings.TrimSpace(tokenMint)
	if store == nil || tokenMint == "" {
		return origin, persistence
	}
	evidence, ok := services.ActorFundingOriginEvidence(origin, network)
	if !ok {
		return origin, persistence
	}
	evidence.TokenMint = tokenMint
	evidence.EvidenceKey = strings.TrimSpace(evidence.EvidenceKey) + ":token:" + tokenMint
	if evidence.Metadata == nil {
		evidence.Metadata = map[string]any{}
	}
	evidence.Metadata["token_context"] = tokenMint
	evidence.Metadata["token_scoped_funding_lineage"] = true
	if err := store.UpsertEvidence(ctx, evidence); err != nil {
		if persistence == "persisted" {
			return origin, "partial_token_context"
		}
		return origin, persistence
	}
	if persistence == "persisted" {
		return origin, "persisted_with_token_context"
	}
	return origin, "token_context_persisted"
}
