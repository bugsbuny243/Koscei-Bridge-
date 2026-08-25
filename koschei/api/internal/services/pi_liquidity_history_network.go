package services

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// enrichPiLiquidityHistoryEvidenceForNetwork preserves the transaction-backed
// liquidity evidence added by the Pi adapter while binding every Horizon read
// and evidence row to the explicitly selected Pi network.
func enrichPiLiquidityHistoryEvidenceForNetwork(ctx context.Context, analysis ArvisAnalysis, target PiRadarTarget, network string) ArvisAnalysis {
	if target.Kind != piRadarTargetKindAsset {
		return analysis
	}
	observation := collectPiLiquidityMovementObservationForNetwork(ctx, target, network)
	if analysis.Bundle.Metadata == nil {
		analysis.Bundle.Metadata = map[string]any{}
	}
	analysis.Bundle.Metadata["pi_liquidity_movement"] = observation
	analysis.Bundle.Metadata["pi_liquidity_movement_source"] = observation.Source
	for index := range analysis.Arms {
		if analysis.Arms[index].ModuleID == ModuleLiquidityMovement {
			analysis.Arms[index] = applyPiLiquidityHistoryToArm(analysis.Arms[index], observation)
			break
		}
	}
	analysis.Bundle.Metadata["arvis_arms"] = analysis.Arms
	return analysis
}

func collectPiLiquidityMovementObservationForNetwork(ctx context.Context, target PiRadarTarget, network string) PiLiquidityMovementObservation {
	normalized, ok := NormalizePiRadarNetwork(network)
	if !ok {
		normalized = DefaultPiRadarNetwork()
	}
	asset := target.AssetCode + ":" + target.Issuer
	source := PiRadarEvidenceSourceForNetwork(normalized) + "_liquidity_operations"
	out := PiLiquidityMovementObservation{
		Status:         "not_observed",
		EvidenceStatus: "insufficient_evidence",
		Source:         source,
		Asset:          asset,
		Movements:      []PiLiquidityMovementRow{},
		Limitations:    []string{},
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	base, err := piHorizonBaseURLForNetwork(normalized)
	if err != nil {
		out.Status = "provider_unavailable"
		out.Limitations = append(out.Limitations, compactPiHorizonError(err))
		return out
	}
	client := &http.Client{Timeout: piHorizonRequestTimeout}
	query := url.Values{
		"reserves": []string{"native," + asset},
		"limit":    []string{strconv.Itoa(piLiquidityHistoryPoolLimit)},
	}
	var pools piHorizonLiquidityPoolDiscoveryPage
	if err := piHorizonGetJSON(ctx, client, base, "/liquidity_pools", query, &pools); err != nil {
		out.Status = "pool_discovery_failed"
		out.Limitations = append(out.Limitations, "Liquidity-pool discovery failed: "+compactPiHorizonError(err))
		return out
	}
	out.PoolsDiscovered = len(pools.Embedded.Records)
	if out.PoolsDiscovered == 0 {
		out.Status = "no_pool_observed"
		out.EvidenceStatus = "observed"
		out.WindowComplete = true
		out.Limitations = append(out.Limitations, "No current native/target-asset liquidity pool was returned by the exact reserve filter; this does not prove that no historical pool ever existed.")
		return out
	}

	poolCount := out.PoolsDiscovered
	if poolCount > piLiquidityHistoryMaxPools {
		poolCount = piLiquidityHistoryMaxPools
		out.Limitations = append(out.Limitations, fmt.Sprintf("Pool discovery returned %d records; movement collection was bounded to %d pools.", out.PoolsDiscovered, piLiquidityHistoryMaxPools))
	}
	out.WindowComplete = out.PoolsDiscovered <= piLiquidityHistoryMaxPools
	for index := 0; index < poolCount; index++ {
		poolID := strings.TrimSpace(pools.Embedded.Records[index].ID)
		if poolID == "" {
			out.WindowComplete = false
			out.Limitations = append(out.Limitations, "A discovered liquidity pool had no usable id and was skipped.")
			continue
		}
		operations, err := collectPiLiquidityPoolOperations(ctx, client, base, poolID, asset)
		if err != nil {
			out.WindowComplete = false
			out.Limitations = append(out.Limitations, "Liquidity operations for pool "+poolID+" could not be collected: "+compactPiHorizonError(err))
			continue
		}
		out.PoolsQueried++
		if len(operations) >= piLiquidityHistoryOperationLimit {
			out.WindowComplete = false
			out.Limitations = append(out.Limitations, "At least one pool reached the configured operation-page limit; movement history is a bounded recent window.")
		}
		for rowIndex := range operations {
			operations[rowIndex].EvidenceSource = source
		}
		out.Movements = append(out.Movements, operations...)
	}

	for _, movement := range out.Movements {
		targetAmount, _ := strconv.ParseFloat(movement.TargetAmount, 64)
		nativeAmount, _ := strconv.ParseFloat(movement.NativeAmount, 64)
		switch movement.Type {
		case "liquidity_pool_deposit":
			out.DepositCount++
			out.TargetDeposited += targetAmount
			out.NativeDeposited += nativeAmount
		case "liquidity_pool_withdraw":
			out.WithdrawCount++
			out.TargetWithdrawn += targetAmount
			out.NativeWithdrawn += nativeAmount
		}
	}
	out.Status = "observed"
	out.EvidenceStatus = "observed"
	if !out.WindowComplete {
		out.Status = "partial_observation"
	}
	if len(out.Movements) == 0 {
		out.Status = "no_movement_observed"
	}
	return out
}
