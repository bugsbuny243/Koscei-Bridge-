package handlers

import (
	"context"
	"math"
	"strings"
	"time"

	"koschei/api/internal/services"
)

// persistLiquidityMovementActorEvidence projects the pool-centric liquidity
// collector into Koschei's persistent actor memory. It does not create a new
// detector or change a grade. The actor index remains evidence-first, and a
// liquidity-removal row can enter the verified exit-event corpus only when the
// parsed transaction signer is also directly related to the investigated
// creator/deployer.
func (h *Handler) persistLiquidityMovementActorEvidence(ctx context.Context, network, mint string, lp services.LPControlEvidence) int {
	if h == nil || h.DB == nil || ctx == nil {
		return 0
	}
	store := services.NewActorDefenseStore(h.DB)
	persisted := 0
	for _, movement := range lp.LiquidityMovements {
		item, ok := liquidityMovementActorEvidence(network, mint, lp, movement)
		if !ok {
			continue
		}
		if err := store.UpsertEvidence(ctx, item); err != nil {
			continue
		}
		persisted++
	}
	return persisted
}

func liquidityMovementActorEvidence(network, mint string, lp services.LPControlEvidence, movement services.LiquidityMovementEvidence) (services.ActorDefenseEvidenceRecord, bool) {
	actor := strings.TrimSpace(movement.ActorWallet)
	signature := strings.TrimSpace(movement.Signature)
	pool := strings.TrimSpace(firstNonEmpty(movement.PoolAddress, lp.PoolAddress))
	program := strings.TrimSpace(firstNonEmpty(movement.Program, lp.PoolProgram))
	mint = strings.TrimSpace(firstNonEmpty(mint, lp.TokenMint))
	if actor == "" || signature == "" || movement.Slot <= 0 || pool == "" || program == "" || mint == "" {
		return services.ActorDefenseEvidenceRecord{}, false
	}

	relation := ""
	switch strings.ToLower(strings.TrimSpace(movement.Kind)) {
	case "remove_liquidity":
		relation = "liquidity_remove_activity"
	case "add_liquidity":
		relation = "liquidity_add_activity"
	case "lock_liquidity":
		relation = "liquidity_lock_activity"
	default:
		return services.ActorDefenseEvidenceRecord{}, false
	}

	verification := strings.ToLower(strings.TrimSpace(movement.VerificationStatus))
	if verification != "verified" && verification != "observed" {
		return services.ActorDefenseEvidenceRecord{}, false
	}
	observedAt := lp.ObservedAt.UTC()
	observedAtBasis := "collector_observed_at"
	if parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(movement.BlockTime)); err == nil && !parsed.IsZero() {
		observedAt = parsed.UTC()
		observedAtBasis = "transaction_block_time"
	}
	if observedAt.IsZero() {
		return services.ActorDefenseEvidenceRecord{}, false
	}

	evidenceKey := strings.TrimSpace(movement.EvidenceKey)
	if evidenceKey == "" {
		evidenceKey = "liquidity_movement:" + strings.ToLower(strings.TrimSpace(movement.Kind)) + ":" + signature
	}
	source := strings.TrimSpace(movement.Source)
	if source == "" {
		source = "solana_rpc"
	}

	return services.ActorDefenseEvidenceRecord{
		Network:            strings.TrimSpace(network),
		ActorWallet:        actor,
		CounterpartKind:    "pool",
		CounterpartID:      pool,
		Relation:           relation,
		VerificationStatus: verification,
		EvidenceKey:        evidenceKey,
		Source:             source,
		Signature:          signature,
		Slot:               movement.Slot,
		ObservedAt:         observedAt,
		TokenMint:          mint,
		TokenAmount:        math.Abs(movement.TokenDelta),
		Metadata: map[string]any{
			"actor_role":               "liquidity_operator",
			"actor_signed":             true,
			"creator_role_observed":    movement.CreatorRelated,
			"creator_relation":         strings.TrimSpace(movement.CreatorRelation),
			"movement_kind":            strings.ToLower(strings.TrimSpace(movement.Kind)),
			"source_wallet":            strings.TrimSpace(movement.SourceWallet),
			"destination_wallet":       strings.TrimSpace(movement.DestinationWallet),
			"pool_account":             pool,
			"program":                  program,
			"instruction_types":        append([]string{}, movement.InstructionTypes...),
			"pool_token_delta":         movement.TokenDelta,
			"pool_quote_delta":         movement.QuoteDelta,
			"transaction_block_time":   strings.TrimSpace(movement.BlockTime),
			"observed_at_basis":        observedAtBasis,
			"identity_or_intent_claim": false,
			"grade_effect":             "none_at_memory_layer",
		},
	}, true
}
