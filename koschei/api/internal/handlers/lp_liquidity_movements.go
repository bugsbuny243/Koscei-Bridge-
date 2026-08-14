package handlers

import (
	"context"
	"fmt"
	"math"
	"sort"
	"strings"
	"time"

	"koschei/api/internal/services"
)

const (
	liquidityMovementSignatureLimit = 50
	liquidityMovementParseLimit     = 20
)

func attachLiquidityMovementEvidence(ctx context.Context, lp services.LPControlEvidence) services.LPControlEvidence {
	lp.LiquidityMovements = append([]services.LiquidityMovementEvidence{}, lp.LiquidityMovements...)
	if strings.TrimSpace(lp.PoolAddress) == "" || strings.TrimSpace(lp.PoolProgram) == "" {
		lp.MovementStatus = "not_applicable"
		return lp
	}
	rpcURL := strings.TrimSpace(creatorIntelRPCURL())
	if rpcURL == "" {
		lp.MovementStatus = "source_unavailable"
		lp.Limitations = append(lp.Limitations, "Solana RPC is unavailable; recent pool add/remove liquidity signatures were not inspected.")
		return lp
	}
	signatures, err := services.SolanaGetSignaturesForAddress(ctx, rpcURL, lp.PoolAddress, liquidityMovementSignatureLimit)
	if err != nil {
		lp.MovementStatus = "source_unavailable"
		lp.MovementWindowFailures++
		lp.Limitations = append(lp.Limitations, "Recent pool signatures could not be read from the configured Solana RPC provider.")
		return lp
	}
	lp.MovementWindowSignatures = len(signatures)
	keys := []string{}
	info := map[string]services.SolanaSignatureInfo{}
	for _, item := range signatures {
		if item.Err != nil || strings.TrimSpace(item.Signature) == "" {
			continue
		}
		keys = append(keys, item.Signature)
		info[item.Signature] = item
		if len(keys) >= liquidityMovementParseLimit {
			break
		}
	}
	if len(keys) == 0 {
		lp.MovementStatus = "complete_no_successful_signatures"
		return lp
	}
	transactions, fetchErr := fetchUnifiedTransactions(ctx, rpcURL, keys)
	if fetchErr != nil {
		lp.MovementWindowFailures++
	}
	for _, signature := range keys {
		tx, ok := transactions[signature]
		if !ok {
			continue
		}
		lp.MovementWindowParsed++
		if movement, observed := parseLiquidityMovement(lp, info[signature], tx); observed {
			lp.LiquidityMovements = append(lp.LiquidityMovements, movement)
			lp.EvidenceKeys = append(lp.EvidenceKeys, movement.EvidenceKey)
		}
	}
	lp.LiquidityMovements = normalizeLiquidityMovements(lp.LiquidityMovements)
	if len(lp.LiquidityMovements) > 0 {
		lp.MovementStatus = "observed"
	} else if fetchErr != nil && lp.MovementWindowParsed == 0 {
		lp.MovementStatus = "collection_failed"
	} else if fetchErr != nil {
		lp.MovementStatus = "partial_no_movement_observed"
	} else {
		lp.MovementStatus = "complete_no_movement_observed"
	}
	lp.Limitations = append(lp.Limitations,
		"Liquidity movement inspection is bounded to the most recent pool signatures and successfully parsed transactions.",
		"A movement row requires an explicit add/remove/lock instruction trace plus compatible vault deltas; reserve direction alone is never classified as liquidity movement.",
		"No movement row means no qualifying add/remove trace was observed in the bounded window; it is not proof that older liquidity activity does not exist.",
	)
	return lp
}

func parseLiquidityMovement(lp services.LPControlEvidence, signature services.SolanaSignatureInfo, tx services.SolanaTransactionResult) (services.LiquidityMovementEvidence, bool) {
	txMap := map[string]any(tx)
	meta := creatorIntelMap(txMap["meta"])
	if meta["err"] != nil {
		return services.LiquidityMovementEvidence{}, false
	}
	message := creatorIntelMap(creatorIntelMap(txMap["transaction"])["message"])
	keys, signers := liquidityAccountKeys(message, meta)
	if !containsLiquidityAccount(keys, lp.PoolAddress) || !containsLiquidityAccount(keys, lp.PoolProgram) {
		return services.LiquidityMovementEvidence{}, false
	}
	instructionTypes, _ := creatorIntelInstructions(message, meta)
	logs := strings.ToLower(strings.Join(creatorIntelStringSlice(meta["logMessages"]), "\n"))
	instructionText := strings.ToLower(strings.Join(instructionTypes, " ") + " " + logs)

	tokenDelta := liquidityTokenAccountDelta(meta, keys, lp.TokenVault, lp.TokenMint)
	quoteDelta := liquidityTokenAccountDelta(meta, keys, lp.QuoteVault, lp.QuoteMint)
	kind := liquidityMovementKind(instructionText, tokenDelta, quoteDelta)
	if kind == "" {
		return services.LiquidityMovementEvidence{}, false
	}
	actor := firstLiquidityActor(signers, lp)
	blockTime := ""
	if raw := creatorIntelInt64(txMap["blockTime"]); raw > 0 {
		blockTime = time.Unix(raw, 0).UTC().Format(time.RFC3339)
	} else if signature.BlockTime != nil && *signature.BlockTime > 0 {
		blockTime = time.Unix(*signature.BlockTime, 0).UTC().Format(time.RFC3339)
	}
	movement := services.LiquidityMovementEvidence{
		Kind: kind, Signature: strings.TrimSpace(signature.Signature), Slot: signature.Slot,
		BlockTime: blockTime, ActorWallet: actor, PoolAddress: lp.PoolAddress, Program: lp.PoolProgram,
		TokenDelta: creatorIntelRound(tokenDelta, 8), QuoteDelta: creatorIntelRound(quoteDelta, 8),
		InstructionTypes: instructionTypes, Source: "solana_jsonparsed_pool_window", VerificationStatus: "VERIFIED",
	}
	movement.CreatorRelated, movement.CreatorRelation = liquidityCreatorRelation(actor, lp)
	switch kind {
	case "add_liquidity":
		movement.SourceWallet, movement.DestinationWallet = actor, lp.PoolAddress
	case "remove_liquidity":
		movement.SourceWallet, movement.DestinationWallet = lp.PoolAddress, actor
	case "lock_liquidity":
		movement.SourceWallet, movement.DestinationWallet = actor, firstNonEmpty(lp.LockerAccount, lp.PoolAddress)
	}
	movement.EvidenceKey = fmt.Sprintf("liquidity_movement:%s:%s:%d", movement.Kind, movement.Signature, movement.Slot)
	return movement, movement.Signature != "" && movement.Slot > 0
}

func liquidityCreatorRelation(actor string, lp services.LPControlEvidence) (bool, string) {
	actor = strings.TrimSpace(actor)
	if actor == "" {
		return false, "signer_unresolved"
	}
	if creator := strings.TrimSpace(lp.PoolCreator); creator != "" && actor == creator {
		return true, "verified_pool_creator_signer"
	}
	if creator := strings.TrimSpace(lp.CreatorWallet); creator != "" && actor == creator {
		return true, "verified_investigated_creator_signer"
	}
	for _, holder := range lp.LargestLPHolders {
		if holder.Classification == "creator" && strings.TrimSpace(holder.OwnerWallet) == actor {
			return true, "verified_creator_lp_holder_signer"
		}
	}
	return false, "not_observed"
}

func liquidityMovementKind(text string, tokenDelta, quoteDelta float64) string {
	const epsilon = 0.000000001
	tokenPresent, quotePresent := math.Abs(tokenDelta) > epsilon, math.Abs(quoteDelta) > epsilon
	normalized := strings.NewReplacer("_", "", "-", "", " ", "").Replace(strings.ToLower(text))
	add := strings.Contains(normalized, "addliquidity") || strings.Contains(normalized, "deposit") || strings.Contains(normalized, "createpool") || strings.Contains(normalized, "initializepool")
	remove := strings.Contains(normalized, "removeliquidity") || strings.Contains(normalized, "withdraw") || strings.Contains(normalized, "closeliquidityposition")
	lock := strings.Contains(normalized, "permanentlock") || strings.Contains(normalized, "lockposition") || strings.Contains(normalized, "lockliquidity")
	if lock {
		return "lock_liquidity"
	}
	if tokenPresent && quotePresent && tokenDelta*quoteDelta < 0 {
		// Opposing reserve deltas describe a swap, regardless of surrounding text.
		return ""
	}
	positiveCompatible := (tokenPresent && tokenDelta > 0) || (quotePresent && quoteDelta > 0)
	negativeCompatible := (tokenPresent && tokenDelta < 0) || (quotePresent && quoteDelta < 0)
	if add && positiveCompatible {
		return "add_liquidity"
	}
	if remove && negativeCompatible {
		return "remove_liquidity"
	}
	return ""
}

func liquidityTokenAccountDelta(meta map[string]any, keys []string, account, mint string) float64 {
	account, mint = strings.TrimSpace(account), strings.TrimSpace(mint)
	if account == "" || mint == "" {
		return 0
	}
	pre := liquidityTokenAccountTotals(meta["preTokenBalances"], keys, account, mint)
	post := liquidityTokenAccountTotals(meta["postTokenBalances"], keys, account, mint)
	return post - pre
}

func liquidityTokenAccountTotals(raw any, keys []string, account, mint string) float64 {
	total := 0.0
	items, _ := raw.([]any)
	for _, rawItem := range items {
		item := creatorIntelMap(rawItem)
		if creatorIntelCleanString(item["mint"]) != mint {
			continue
		}
		index, indexOK := safeIntFromInt64(creatorIntelInt64(item["accountIndex"]))
		if !indexOK || index < 0 || index >= len(keys) || strings.TrimSpace(keys[index]) != account {
			continue
		}
		total += creatorIntelUIAmount(creatorIntelMap(item["uiTokenAmount"]))
	}
	return total
}

func liquidityAccountKeys(message, meta map[string]any) ([]string, []string) {
	keys, signers := creatorIntelAccountKeys(message)
	loaded := creatorIntelMap(meta["loadedAddresses"])
	keys = append(keys, creatorIntelStringSlice(loaded["writable"])...)
	keys = append(keys, creatorIntelStringSlice(loaded["readonly"])...)
	return keys, signers
}

func firstLiquidityActor(signers []string, lp services.LPControlEvidence) string {
	excluded := map[string]bool{}
	for _, value := range []string{lp.PoolAddress, lp.PoolProgram, lp.TokenVault, lp.QuoteVault, lp.TokenMint, lp.QuoteMint, lp.LPMint, lp.LockerAccount, lp.LockerProgram} {
		value = strings.TrimSpace(value)
		if value != "" {
			excluded[value] = true
		}
	}
	for _, signer := range signers {
		signer = strings.TrimSpace(signer)
		if signer != "" && !excluded[signer] {
			return signer
		}
	}
	return ""
}

func containsLiquidityAccount(values []string, target string) bool {
	target = strings.TrimSpace(target)
	for _, value := range values {
		if strings.TrimSpace(value) == target {
			return true
		}
	}
	return false
}

func normalizeLiquidityMovements(values []services.LiquidityMovementEvidence) []services.LiquidityMovementEvidence {
	seen := map[string]bool{}
	out := []services.LiquidityMovementEvidence{}
	for _, value := range values {
		value.Signature = strings.TrimSpace(value.Signature)
		value.EvidenceKey = strings.TrimSpace(value.EvidenceKey)
		if value.Signature == "" || value.Slot <= 0 {
			continue
		}
		key := value.Kind + "|" + value.Signature
		if seen[key] {
			continue
		}
		seen[key] = true
		value.InstructionTypes = uniqueStrings(value.InstructionTypes)
		out = append(out, value)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Slot == out[j].Slot {
			return out[i].Signature < out[j].Signature
		}
		return out[i].Slot > out[j].Slot
	})
	return out
}
