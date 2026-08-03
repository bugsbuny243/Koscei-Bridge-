package handlers

import (
	"context"
	"strings"
	"time"

	"koschei/api/internal/services"
)

// resolveCanonicalCreatorSourceContext closes the entry-point gap between a
// manually submitted mint and the actor investigation pipeline. Existing
// chain/source evidence always wins. Helius metadata and history are
// discovery-only: they may start the actor investigation as OBSERVED evidence,
// but cannot mark the creator relation VERIFIED without canonical RPC signer
// and instruction verification.
func (h *Handler) resolveCanonicalCreatorSourceContext(ctx context.Context, target, network, mode string, source map[string]any) map[string]any {
	out := cloneCreatorSourceContext(source)
	if creator := strings.TrimSpace(creatorIntelCleanString(out["creator_wallet"])); creator != "" {
		out["creator_resolution_status"] = "source_context"
		return out
	}
	if !unifiedLiveEvidenceAllowed(mode) {
		out["creator_resolution_status"] = "not_requested"
		return out
	}

	metadata := services.FetchHeliusTokenMetadata(ctx, strings.TrimSpace(creatorIntelRPCURL()), target)
	out["creator_resolution"] = metadata
	out["creator_resolution_provider"] = metadata.Provider
	out["creator_resolution_status"] = metadata.Status
	if !metadata.Available {
		return out
	}
	out["available"] = true
	out["network"] = firstNonEmptyString(strings.TrimSpace(network), "solana-mainnet")
	out["token_name"] = firstNonEmptyString(creatorIntelCleanString(out["token_name"]), metadata.Name)
	out["token_symbol"] = firstNonEmptyString(creatorIntelCleanString(out["token_symbol"]), metadata.Symbol)
	out["token_2022_extensions"] = metadata.OnchainExtensions
	if strings.TrimSpace(metadata.Creator) == "" {
		out["creator_resolution_status"] = "metadata_without_creator"
		return out
	}

	observedAt := metadata.ObservedAt
	if !metadata.CreatedAt.IsZero() {
		observedAt = metadata.CreatedAt
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	out["source"] = "helius_das_and_rpc"
	out["source_address"] = strings.TrimSpace(metadata.Creator)
	out["creator_wallet"] = strings.TrimSpace(metadata.Creator)
	out["creator_label"] = "Helius creator discovery"
	out["creator_relation_verified"] = false
	out["creator_relation_observed"] = true
	out["creator_resolution_status"] = "observed_external_attribution"
	out["creator_scope"] = "Helius DAS and transaction-history discovery only; canonical RPC create-transaction signer verification is required before VERIFIED status."
	out["signature"] = strings.TrimSpace(metadata.CreateTransaction)
	out["creation_signature"] = strings.TrimSpace(metadata.CreateTransaction)
	out["launch_signature"] = strings.TrimSpace(metadata.CreateTransaction)
	out["observed_at"] = observedAt.UTC().Format(time.RFC3339)
	if metadata.CreatedTime > 0 {
		out["created_time"] = metadata.CreatedTime
	}
	if strings.TrimSpace(metadata.FirstMintTransaction) != "" {
		out["first_mint_signature"] = strings.TrimSpace(metadata.FirstMintTransaction)
	}
	return out
}

func cloneCreatorSourceContext(source map[string]any) map[string]any {
	out := map[string]any{}
	for key, value := range source {
		out[key] = value
	}
	if _, ok := out["available"]; !ok {
		out["available"] = false
	}
	if _, ok := out["identity_claimed"]; !ok {
		out["identity_claimed"] = false
	}
	return out
}
