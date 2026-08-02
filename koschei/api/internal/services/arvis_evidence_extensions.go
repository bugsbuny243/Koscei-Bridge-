package services

import (
	"fmt"
	"strings"
	"time"
)

// ApplyCreatorAndLiquidityEvidenceToAnalysis replaces creator, liquidity and
// DEX-specific pool placeholders after the handler has collected source metadata
// and market depth. It does not recalculate holder evidence and cannot issue a
// grade.
func ApplyCreatorAndLiquidityEvidenceToAnalysis(analysis ArvisAnalysis, req SecurityRadarRequest, creator string, market TokenMarketSnapshot, launch LaunchForensicsAnalysis) ArvisAnalysis {
	generatedAt := time.Now().UTC().Format(time.RFC3339)
	creator = strings.TrimSpace(creator)
	replacements := map[string]SecurityRadarVerdict{
		ModuleCreatorLinkAnalysis: creatorLinkEvidenceArm(req, creator, launch, generatedAt),
		ModuleLiquidityMovement:   liquidityMovementEvidenceArm(req, market, generatedAt),
		ModuleRaydiumPoolGuardian: raydiumMarketEvidenceArm(req, market, generatedAt),
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
	analysis.Bundle.Metadata["creator_link_analysis"] = replacements[ModuleCreatorLinkAnalysis]
	analysis.Bundle.Metadata["liquidity_movement"] = replacements[ModuleLiquidityMovement]
	analysis.Bundle.Metadata["raydium_pool_guardian"] = replacements[ModuleRaydiumPoolGuardian]
	analysis.Bundle.Metadata["verified_arm_count"] = verifiedArvisEvidenceCount(updated)
	analysis.Bundle.Metadata["runtime_arm_count"] = verifiedArvisEvidenceCount(updated)
	analysis.Bundle.Metadata["final_verdict_source"] = "EvaluateUnifiedRadarVerdict"
	return ApplyArvisInvestigationCoverage(analysis)
}

func creatorLinkEvidenceArm(req SecurityRadarRequest, creator string, launch LaunchForensicsAnalysis, generatedAt string) SecurityRadarVerdict {
	if creator == "" {
		return evidencePendingArm("Creator Link Analysis", ModuleCreatorLinkAnalysis, req, generatedAt, "Creator/deployer wallet was not present in the source or parsed launch context.", "creator_relation_unresolved")
	}
	signals := map[string]any{
		"module_id":                         ModuleCreatorLinkAnalysis,
		"real_onchain_evidence":             true,
		"evidence_status":                   "observed",
		"execution_status":                  ArvisExecutionCompleted,
		"collector_attempted":               true,
		"applicable":                        true,
		"finding_observed":                  true,
		"creator_wallet":                    creator,
		"observed_role":                     "creator_deployer",
		"creator_linked_launch_actor_count": launch.CreatorLinkedCount,
		"launch_data_source":                launch.DataSource,
		"identity_or_wrongdoing_claim":      false,
		"numeric_score_disabled":            true,
		"grade_effect":                      "none_at_arm_layer",
	}
	evidence := []string{
		fmt.Sprintf("Creator/deployer wallet observed for mint %s: %s.", req.Target, creator),
		"This relation is an on-chain/source observation and is not a real-world identity or wrongdoing claim.",
	}
	if launch.CreatorLinkedCount > 0 {
		evidence = append(evidence, fmt.Sprintf("Launch analysis observed %d recipient/holder profile(s) with creator-linked funding evidence.", launch.CreatorLinkedCount))
	}
	arm := evidenceArm("Creator Link Analysis", ModuleCreatorLinkAnalysis, req, 0, signals, evidence, generatedAt)
	arm.Verdict = "Creator/deployer relation observed; cross-token reuse is owned by Repeat Actor Scan and final interpretation belongs to the unified rules engine."
	arm.Recommendation = "Inspect persistent created-token history and direct creator-to-holder transaction evidence."
	return arm
}

func liquidityMovementEvidenceArm(req SecurityRadarRequest, market TokenMarketSnapshot, generatedAt string) SecurityRadarVerdict {
	if !market.Available || market.LiquidityUSD <= 0 {
		v := evidencePendingArm("Liquidity Movement", ModuleLiquidityMovement, req, generatedAt, "A positive pool-liquidity snapshot or parsed LP transaction is required; missing liquidity is not a low-risk signal.", "liquidity_snapshot_unavailable")
		v.Signals["market_snapshot"] = market
		for _, limitation := range market.Limitations {
			v.Evidence = append(v.Evidence, "Limitation: "+limitation)
		}
		return v
	}
	observedAt := market.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	signals := map[string]any{
		"module_id":                          ModuleLiquidityMovement,
		"real_offchain_evidence":             true,
		"evidence_status":                    "observed_market_snapshot",
		"execution_status":                   ArvisExecutionCompleted,
		"collector_attempted":                true,
		"applicable":                         true,
		"finding_observed":                   true,
		"provider":                           market.Provider,
		"liquidity_usd":                      market.LiquidityUSD,
		"best_pair_address":                  market.BestPairAddress,
		"best_pair_dex":                      market.BestPairDEX,
		"best_pair_liquidity_usd":            market.BestPairLiquidityUSD,
		"best_pair_volume_24h_usd":           market.BestPairVolume24hUSD,
		"pair_count":                         market.PairCount,
		"observed_at":                        observedAt.UTC().Format(time.RFC3339),
		"valuation_scope":                    market.ValuationScope,
		"lp_add_remove_transaction_verified": false,
		"lp_control_resolved":                false,
		"numeric_score_disabled":             true,
		"grade_effect":                       "none_at_arm_layer",
	}
	evidence := []string{
		fmt.Sprintf("Market provider %s reported $%.2f liquidity across %d Solana pair(s).", market.Provider, market.LiquidityUSD, market.PairCount),
		fmt.Sprintf("Most liquid pair %s on %s reported $%.2f liquidity.", firstRadarValue(market.BestPairAddress, "unknown"), firstRadarValue(market.BestPairDEX, "unknown"), market.BestPairLiquidityUSD),
		"This snapshot describes pool depth; it does not claim who added or removed liquidity without parsed LP transaction evidence.",
	}
	for _, limitation := range market.Limitations {
		evidence = append(evidence, "Limitation: "+limitation)
	}
	arm := evidenceArm("Liquidity Movement", ModuleLiquidityMovement, req, 0, signals, evidence, generatedAt)
	arm.Verdict = "Liquidity depth was observed. LP actor attribution remains unverified until transaction-backed add/remove evidence exists."
	arm.Recommendation = "Use liquidity depth as input to URD-C001/URD-C002 and parsed LP transactions for creator-removal hard triggers."
	return arm
}

func raydiumMarketEvidenceArm(req SecurityRadarRequest, market TokenMarketSnapshot, generatedAt string) SecurityRadarVerdict {
	if !market.Available || strings.TrimSpace(market.BestPairAddress) == "" {
		v := evidencePendingArm("Raydium Pool Guardian", ModuleRaydiumPoolGuardian, req, generatedAt, "A resolved market pair is required before the Raydium-specific pool collector can be classified.", "pool_pair_unresolved")
		v.Signals["market_snapshot"] = market
		return v
	}
	dex := strings.ToLower(strings.TrimSpace(market.BestPairDEX))
	if !strings.Contains(dex, "raydium") {
		v := notApplicableArm("Raydium Pool Guardian", ModuleRaydiumPoolGuardian, req, generatedAt, fmt.Sprintf("The most liquid observed pair is on %s, so the Raydium-specific collector is not applicable to this primary pair.", firstRadarValue(market.BestPairDEX, "another DEX")), "primary_pair_not_raydium")
		v.Signals["market_snapshot"] = market
		v.Signals["best_pair_address"] = market.BestPairAddress
		v.Signals["best_pair_dex"] = market.BestPairDEX
		return v
	}
	observedAt := market.ObservedAt
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	signals := map[string]any{
		"module_id":                          ModuleRaydiumPoolGuardian,
		"real_offchain_evidence":             true,
		"evidence_status":                    "observed_raydium_market_pair",
		"execution_status":                   ArvisExecutionCompleted,
		"collector_attempted":                true,
		"applicable":                         true,
		"finding_observed":                   true,
		"provider":                           market.Provider,
		"best_pair_address":                  market.BestPairAddress,
		"best_pair_dex":                      market.BestPairDEX,
		"best_pair_liquidity_usd":            market.BestPairLiquidityUSD,
		"best_pair_volume_24h_usd":           market.BestPairVolume24hUSD,
		"observed_at":                        observedAt.UTC().Format(time.RFC3339),
		"lp_owner_resolved":                  false,
		"lp_lock_status_resolved":            false,
		"lp_add_remove_transaction_verified": false,
		"numeric_score_disabled":             true,
		"grade_effect":                       "none_at_arm_layer",
	}
	evidence := []string{
		fmt.Sprintf("The primary observed market pair %s is reported on %s.", market.BestPairAddress, market.BestPairDEX),
		fmt.Sprintf("The reported Raydium pair depth is $%.2f with $%.2f observed 24h volume.", market.BestPairLiquidityUSD, market.BestPairVolume24hUSD),
		"Pool venue and depth were observed from the market snapshot; LP owner, burn/lock and add/remove transactions are not yet resolved by this evidence line.",
	}
	arm := evidenceArm("Raydium Pool Guardian", ModuleRaydiumPoolGuardian, req, 0, signals, evidence, generatedAt)
	arm.Verdict = "A Raydium primary market pair and its reported depth were observed; LP control remains an explicit evidence gap."
	arm.Recommendation = "Resolve pool reserves, LP mint ownership, burn/locker proof and parsed add/remove signatures."
	return arm
}
