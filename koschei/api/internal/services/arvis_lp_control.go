package services

import (
	"fmt"
	"strings"
	"time"
)

// ApplyLPControlEvidenceToAnalysis replaces only the pool/liquidity evidence
// view. It does not recalculate or cap a grade and cannot alter signing.
func ApplyLPControlEvidenceToAnalysis(analysis ArvisAnalysis, req SecurityRadarRequest, lp LPControlEvidence) ArvisAnalysis {
	generatedAt := time.Now().UTC().Format(time.RFC3339)
	poolArm := lpControlPoolArm(req, lp, generatedAt)
	liquidityArm := lpControlLiquidityArm(req, lp, generatedAt)
	replacements := map[string]SecurityRadarVerdict{
		ModuleRaydiumPoolGuardian: poolArm,
		ModuleLiquidityMovement:   liquidityArm,
	}
	arms := ArvisArmsFromBundle(analysis.Bundle)
	if len(arms) == 0 {
		arms = append([]SecurityRadarVerdict{}, analysis.Arms...)
	}
	updated := make([]SecurityRadarVerdict, 0, len(arms))
	seen := map[string]bool{}
	for _, arm := range arms {
		if replacement, ok := replacements[arm.ModuleID]; ok {
			updated = append(updated, replacement)
			seen[arm.ModuleID] = true
			continue
		}
		updated = append(updated, arm)
	}
	for moduleID, replacement := range replacements {
		if !seen[moduleID] {
			updated = append(updated, replacement)
		}
	}
	analysis.Arms = updated
	analysis.Final = arvisCompatibilityFinal()
	if analysis.Bundle.Metadata == nil {
		analysis.Bundle.Metadata = map[string]any{}
	}
	analysis.Bundle.Metadata["arvis_arms"] = updated
	analysis.Bundle.Metadata["lp_control"] = lp
	analysis.Bundle.Metadata["raydium_pool_guardian"] = poolArm
	analysis.Bundle.Metadata["pool_control_guardian"] = poolArm
	analysis.Bundle.Metadata["liquidity_movement"] = liquidityArm
	analysis.Bundle.Metadata["verified_arm_count"] = verifiedArvisEvidenceCount(updated)
	analysis.Bundle.Metadata["runtime_arm_count"] = verifiedArvisEvidenceCount(updated)
	return ApplyArvisInvestigationCoverage(analysis)
}

func lpControlPoolArm(req SecurityRadarRequest, lp LPControlEvidence, generatedAt string) SecurityRadarVerdict {
	const moduleName = "Pool Control Guardian"
	if lp.Status == LPControlNotApplicable {
		return notApplicableArm(moduleName, ModuleRaydiumPoolGuardian, req, generatedAt, lpControlReason(lp), lp.ReasonCode)
	}
	if lp.Status == LPControlSourceUnavailable || strings.TrimSpace(lp.PoolAddress) == "" {
		arm := evidencePendingArm(moduleName, ModuleRaydiumPoolGuardian, req, generatedAt, lpControlReason(lp), firstRadarValue(lp.ReasonCode, "pool_control_unavailable"))
		arm.Signals["execution_status"] = ArvisExecutionSourceUnavailable
		arm.Signals["lp_control"] = lp
		return arm
	}
	if !lp.Available {
		arm := evidencePendingArm(moduleName, ModuleRaydiumPoolGuardian, req, generatedAt, lpControlReason(lp), firstRadarValue(lp.ReasonCode, "pool_control_incomplete"))
		arm.Signals["execution_status"] = ArvisExecutionInsufficient
		arm.Signals["pool_address"] = lp.PoolAddress
		arm.Signals["pool_program"] = lp.PoolProgram
		arm.Signals["lp_control"] = lp
		return arm
	}
	status := "observed"
	verified := lp.Status == LPControlVerifiedBurned || lp.Status == LPControlVerifiedLocked || lp.Status == LPControlVerifiedPermanentLocked
	if verified {
		status = "verified"
	}
	movementSignatures, movementSlots, movementActors, movementKinds := lpMovementReferences(lp.LiquidityMovements)
	signals := map[string]any{
		"module_id":                      ModuleRaydiumPoolGuardian,
		"execution_status":               ArvisExecutionCompleted,
		"collector_attempted":            true,
		"applicable":                     true,
		"finding_observed":               true,
		"real_onchain_evidence":          true,
		"evidence_status":                status,
		"pool_address":                   lp.PoolAddress,
		"pool_program":                   lp.PoolProgram,
		"pool_type":                      lp.PoolType,
		"control_model":                  lp.ControlModel,
		"position_model":                 lp.PositionModel,
		"pool_creator":                   lp.PoolCreator,
		"creator_wallet":                 lp.CreatorWallet,
		"canonical_pool":                 lp.CanonicalPool,
		"lp_mint":                        lp.LPMint,
		"token_vault":                    lp.TokenVault,
		"quote_vault":                    lp.QuoteVault,
		"read_slot":                      lp.ReadSlot,
		"token_reserve":                  lp.TokenReserve,
		"quote_reserve":                  lp.QuoteReserve,
		"virtual_quote_reserve":          lp.VirtualQuoteReserve,
		"effective_quote_reserve":        lp.EffectiveQuoteReserve,
		"reserve_liquidity_usd":          lp.ReserveLiquidityUSD,
		"reserve_value_source":           lp.ReserveValueSource,
		"lp_supply":                      lp.LPSupply,
		"lp_supply_source":               lp.LPSupplySource,
		"lp_lock_status":                 lp.Status,
		"burned_share_pct":               lp.BurnedSharePct,
		"creator_lp_share_pct":           lp.CreatorLPSharePct,
		"dominant_lp_owner":              lp.DominantLPOwner,
		"dominant_lp_token_account":      lp.DominantLPTokenAccount,
		"dominant_lp_share_pct":          lp.DominantLPSharePct,
		"dominant_lp_classification":     lp.DominantLPClassification,
		"creator_relation":               lp.CreatorRelation,
		"locked_lp_amount":               lp.LockedLPAmount,
		"locked_lp_share_pct":            lp.LockedLPSharePct,
		"locked_lp_token_accounts":       append([]string{}, lp.LockedLPTokenAccounts...),
		"locked_lp_authority_accounts":   append([]string{}, lp.LockedLPAuthorityAccounts...),
		"locked_position_count":          lp.LockedPositionCount,
		"locked_position_liquidity_raw":  lp.LockedPositionLiquidityRaw,
		"position_enumeration_status":    lp.PositionEnumerationStatus,
		"position_enumeration_limit":     lp.PositionEnumerationLimit,
		"locked_positions":               append([]CLMMLockedPositionEvidence{}, lp.LockedPositions...),
		"pool_liquidity_raw":             lp.PoolLiquidityRaw,
		"permanent_locked_liquidity_raw": lp.PermanentLockedLiquidityRaw,
		"permanent_locked_share_pct":     lp.PermanentLockedSharePct,
		"locker_program":                 lp.LockerProgram,
		"locker_account":                 lp.LockerAccount,
		"locked_until":                   lp.LockedUntil,
		"movement_status":                lp.MovementStatus,
		"liquidity_movement_count":       len(lp.LiquidityMovements),
		"liquidity_movement_signatures":  movementSignatures,
		"liquidity_movement_slots":       movementSlots,
		"liquidity_movement_actors":      movementActors,
		"liquidity_movement_kinds":       movementKinds,
		"liquidity_movements":            append([]LiquidityMovementEvidence{}, lp.LiquidityMovements...),
		"evidence_keys":                  append([]string{}, lp.EvidenceKeys...),
		"numeric_score_disabled":         true,
		"grade_effect":                   "none_at_arm_layer",
	}
	evidence := []string{
		fmt.Sprintf("Pool %s is owned by pinned program %s, decoded as %s, and read at slot %d.", lp.PoolAddress, lp.PoolProgram, firstRadarValue(lp.PoolType, "unclassified_pool"), lp.ReadSlot),
		fmt.Sprintf("Control model %s; token vault %s reserve %.8f; quote vault %s reserve %.8f.", firstRadarValue(lp.ControlModel, "unresolved"), lp.TokenVault, lp.TokenReserve, lp.QuoteVault, lp.QuoteReserve),
	}
	if lp.ControlModel == "lp_token" {
		evidence = append(evidence, fmt.Sprintf("LP mint %s supply %.8f; burn-address share %.4f%%; creator-observed share %.4f%%.", lp.LPMint, lp.LPSupply, lp.BurnedSharePct, lp.CreatorLPSharePct))
		evidence = append(evidence, fmt.Sprintf("Dominant resolved LP owner %s controls %.4f%% via token account %s (%s); creator relation %s.", lp.DominantLPOwner, lp.DominantLPSharePct, lp.DominantLPTokenAccount, lp.DominantLPClassification, lp.CreatorRelation))
		if lp.LockedLPSharePct > 0 {
			evidence = append(evidence, fmt.Sprintf("Pinned Raydium CPMM Burn & Earn custody was resolved for %.8f LP tokens (%.4f%% of observed mint supply) across %d LP token accounts and %d authority accounts; program %s.", lp.LockedLPAmount, lp.LockedLPSharePct, len(lp.LockedLPTokenAccounts), len(lp.LockedLPAuthorityAccounts), lp.LockerProgram))
		}
	}
	if lp.ControlModel == "position_nft" {
		if lp.PositionModel == "raydium_clmm_position_nft" {
			evidence = append(evidence, fmt.Sprintf("Raydium CLMM position model: pool active-liquidity raw %s; %d VERIFIED Burn & Earn positions sum to locked position-liquidity raw %s; enumeration %s with fail-closed limit %d.", lp.PoolLiquidityRaw, lp.LockedPositionCount, firstRadarValue(lp.LockedPositionLiquidityRaw, "0"), lp.PositionEnumerationStatus, lp.PositionEnumerationLimit))
			for _, position := range lp.LockedPositions {
				evidence = append(evidence, fmt.Sprintf("CLMM lock %s VERIFIED: original owner %s, personal position %s, position NFT mint %s, locked NFT account %s held by program authority %s, ticks [%d,%d], liquidity raw %s, fee NFT mint %s.", position.LockedPositionAccount, position.PositionOwner, position.PositionAccount, position.PositionNFTMint, position.LockedNFTAccount, position.CustodyAuthority, position.TickLowerIndex, position.TickUpperIndex, position.LiquidityRaw, position.FeeNFTMint))
			}
		} else {
			evidence = append(evidence, fmt.Sprintf("Position model %s; pool liquidity raw %s; permanent locked liquidity raw %s (%.4f%%).", lp.PositionModel, lp.PoolLiquidityRaw, lp.PermanentLockedLiquidityRaw, lp.PermanentLockedSharePct))
		}
	}
	for _, movement := range lp.LiquidityMovements {
		evidence = append(evidence, fmt.Sprintf("%s VERIFIED in signature %s at slot %d; source %s, destination %s, pool token delta %.8f, quote delta %.8f, creator relation %s.", movement.Kind, movement.Signature, movement.Slot, movement.SourceWallet, movement.DestinationWallet, movement.TokenDelta, movement.QuoteDelta, movement.CreatorRelation))
	}
	for _, key := range lp.EvidenceKeys {
		evidence = append(evidence, "Evidence key: "+key)
	}
	for _, limitation := range lp.Limitations {
		evidence = append(evidence, "Limitation: "+limitation)
	}
	arm := evidenceArm(moduleName, ModuleRaydiumPoolGuardian, req, 0, signals, evidence, generatedAt)
	arm.Verdict = "Pool reserves and protocol-specific control surfaces were collected directly from Solana accounts; the status describes observed capability, not intent."
	arm.Recommendation = "none"
	return arm
}

func lpControlLiquidityArm(req SecurityRadarRequest, lp LPControlEvidence, generatedAt string) SecurityRadarVerdict {
	if lp.Status == LPControlNotApplicable {
		return notApplicableArm("Liquidity Movement", ModuleLiquidityMovement, req, generatedAt, lpControlReason(lp), lp.ReasonCode)
	}
	if lp.Status == LPControlSourceUnavailable || strings.TrimSpace(lp.PoolAddress) == "" {
		arm := evidencePendingArm("Liquidity Movement", ModuleLiquidityMovement, req, generatedAt, lpControlReason(lp), firstRadarValue(lp.ReasonCode, "reserve_collection_unavailable"))
		arm.Signals["execution_status"] = ArvisExecutionSourceUnavailable
		arm.Signals["lp_control"] = lp
		return arm
	}
	if !lp.Available {
		arm := evidencePendingArm("Liquidity Movement", ModuleLiquidityMovement, req, generatedAt, lpControlReason(lp), firstRadarValue(lp.ReasonCode, "reserve_collection_incomplete"))
		arm.Signals["execution_status"] = ArvisExecutionInsufficient
		arm.Signals["pool_address"] = lp.PoolAddress
		arm.Signals["pool_program"] = lp.PoolProgram
		arm.Signals["lp_control"] = lp
		return arm
	}
	arm := lpControlPoolArm(req, lp, generatedAt)
	arm.Module = "Liquidity Movement"
	arm.ModuleID = ModuleLiquidityMovement
	arm.Signals["module_id"] = ModuleLiquidityMovement
	arm.Signals["liquidity_movement_transaction_verified"] = len(lp.LiquidityMovements) > 0
	arm.Signals["movement_evidence_status"] = func() string {
		if len(lp.LiquidityMovements) > 0 {
			return "verified"
		}
		return "not_observed_in_bounded_window"
	}()
	arm.Signals["reserve_snapshot_verified"] = lp.ReadSlot > 0 && lp.TokenVault != "" && lp.QuoteVault != ""
	arm.Verdict = "Pool reserve balances were read at the reported slot. Add/remove liquidity is reported only when an explicit liquidity instruction trace carries compatible vault deltas."
	return arm
}

func lpMovementReferences(values []LiquidityMovementEvidence) ([]string, []int64, []string, []string) {
	signatures, actors, kinds := []string{}, []string{}, []string{}
	slots := []int64{}
	for _, value := range values {
		signatures = append(signatures, value.Signature)
		actors = append(actors, value.ActorWallet)
		kinds = append(kinds, value.Kind)
		if value.Slot > 0 {
			slots = append(slots, value.Slot)
		}
	}
	return uniqueRadarStrings(signatures), uniqueRadarInt64s(slots), uniqueRadarStrings(actors), uniqueRadarStrings(kinds)
}

func uniqueRadarStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func uniqueRadarInt64s(values []int64) []int64 {
	seen := map[int64]bool{}
	out := []int64{}
	for _, value := range values {
		if value <= 0 || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func lpControlReason(lp LPControlEvidence) string {
	if len(lp.Limitations) > 0 && strings.TrimSpace(lp.Limitations[0]) != "" {
		return lp.Limitations[0]
	}
	if lp.ReasonCode != "" {
		return lp.ReasonCode
	}
	return "LP control evidence was not available for this scan."
}
