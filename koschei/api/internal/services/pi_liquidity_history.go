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

const (
	piLiquidityHistoryPoolLimit      = 20
	piLiquidityHistoryMaxPools       = 8
	piLiquidityHistoryOperationLimit = 100
	piLiquidityHistorySource         = "pi_horizon_liquidity_operations"
)

type PiLiquidityMovementObservation struct {
	Status          string                   `json:"status"`
	EvidenceStatus  string                   `json:"evidence_status"`
	Source          string                   `json:"source"`
	Asset           string                   `json:"asset"`
	PoolsDiscovered int                      `json:"pools_discovered"`
	PoolsQueried    int                      `json:"pools_queried"`
	WindowComplete  bool                     `json:"window_complete"`
	DepositCount    int                      `json:"deposit_count"`
	WithdrawCount   int                      `json:"withdraw_count"`
	TargetDeposited float64                  `json:"target_deposited"`
	TargetWithdrawn float64                  `json:"target_withdrawn"`
	NativeDeposited float64                  `json:"native_deposited"`
	NativeWithdrawn float64                  `json:"native_withdrawn"`
	Movements       []PiLiquidityMovementRow `json:"movements"`
	Limitations     []string                 `json:"limitations,omitempty"`
	GeneratedAt     string                   `json:"generated_at"`
}

type PiLiquidityMovementRow struct {
	PoolID             string `json:"pool_id"`
	OperationID        string `json:"operation_id"`
	Type               string `json:"type"`
	TransactionHash    string `json:"transaction_hash"`
	SourceAccount      string `json:"source_account"`
	Timestamp          string `json:"timestamp"`
	TargetAsset        string `json:"target_asset"`
	TargetAmount       string `json:"target_amount"`
	NativeAmount       string `json:"native_amount,omitempty"`
	Shares             string `json:"shares,omitempty"`
	VerificationStatus string `json:"verification_status"`
	EvidenceSource     string `json:"evidence_source"`
}

type piHorizonLiquidityOperation struct {
	ID                string                     `json:"id"`
	Type              string                     `json:"type"`
	TransactionHash   string                     `json:"transaction_hash"`
	SourceAccount     string                     `json:"source_account"`
	CreatedAt         string                     `json:"created_at"`
	LiquidityPoolID   string                     `json:"liquidity_pool_id"`
	ReservesDeposited []piHorizonLiquidityAmount `json:"reserves_deposited"`
	ReservesReceived  []piHorizonLiquidityAmount `json:"reserves_received"`
	SharesReceived    string                     `json:"shares_received"`
	Shares            string                     `json:"shares"`
}

type piHorizonLiquidityAmount struct {
	Asset  string `json:"asset"`
	Amount string `json:"amount"`
}

type piHorizonLiquidityOperationPage struct {
	Embedded struct {
		Records []piHorizonLiquidityOperation `json:"records"`
	} `json:"_embedded"`
}

type piHorizonLiquidityPoolDiscoveryPage struct {
	Embedded struct {
		Records []struct {
			ID string `json:"id"`
		} `json:"records"`
	} `json:"_embedded"`
}

// enrichPiLiquidityHistoryEvidence adds successful Horizon liquidity-pool
// deposit/withdraw operations as transaction-backed movement evidence. It does
// not derive a risk grade and does not pretend the bounded operation page is a
// complete historical ledger.
func enrichPiLiquidityHistoryEvidence(ctx context.Context, analysis ArvisAnalysis, target PiRadarTarget) ArvisAnalysis {
	if target.Kind != piRadarTargetKindAsset {
		return analysis
	}
	observation := collectPiLiquidityMovementObservation(ctx, target)
	if analysis.Bundle.Metadata == nil {
		analysis.Bundle.Metadata = map[string]any{}
	}
	analysis.Bundle.Metadata["pi_liquidity_movement"] = observation
	analysis.Bundle.Metadata["pi_liquidity_movement_source"] = piLiquidityHistorySource
	for index := range analysis.Arms {
		if analysis.Arms[index].ModuleID == ModuleLiquidityMovement {
			analysis.Arms[index] = applyPiLiquidityHistoryToArm(analysis.Arms[index], observation)
			break
		}
	}
	analysis.Bundle.Metadata["arvis_arms"] = analysis.Arms
	return analysis
}

func collectPiLiquidityMovementObservation(ctx context.Context, target PiRadarTarget) PiLiquidityMovementObservation {
	asset := target.AssetCode + ":" + target.Issuer
	out := PiLiquidityMovementObservation{
		Status:         "not_observed",
		EvidenceStatus: "insufficient_evidence",
		Source:         piLiquidityHistorySource,
		Asset:          asset,
		Movements:      []PiLiquidityMovementRow{},
		Limitations:    []string{},
		GeneratedAt:    time.Now().UTC().Format(time.RFC3339),
	}
	base, err := piHorizonBaseURL()
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

func collectPiLiquidityPoolOperations(ctx context.Context, client *http.Client, base *url.URL, poolID, targetAsset string) ([]PiLiquidityMovementRow, error) {
	query := url.Values{
		"order": []string{"desc"},
		"limit": []string{strconv.Itoa(piLiquidityHistoryOperationLimit)},
	}
	var page piHorizonLiquidityOperationPage
	path := "/liquidity_pools/" + url.PathEscape(poolID) + "/operations"
	if err := piHorizonGetJSON(ctx, client, base, path, query, &page); err != nil {
		return nil, err
	}
	rows := make([]PiLiquidityMovementRow, 0, len(page.Embedded.Records))
	for _, operation := range page.Embedded.Records {
		row, ok := piLiquidityMovementRow(operation, poolID, targetAsset)
		if ok {
			rows = append(rows, row)
		}
	}
	return rows, nil
}

func piLiquidityMovementRow(operation piHorizonLiquidityOperation, fallbackPoolID, targetAsset string) (PiLiquidityMovementRow, bool) {
	movementType := strings.ToLower(strings.TrimSpace(operation.Type))
	var amounts []piHorizonLiquidityAmount
	shares := ""
	switch movementType {
	case "liquidity_pool_deposit":
		amounts = operation.ReservesDeposited
		shares = operation.SharesReceived
	case "liquidity_pool_withdraw":
		amounts = operation.ReservesReceived
		shares = operation.Shares
	default:
		return PiLiquidityMovementRow{}, false
	}
	targetAmount := piLiquidityReserveAmount(amounts, targetAsset)
	if targetAmount == "" {
		return PiLiquidityMovementRow{}, false
	}
	poolID := strings.TrimSpace(operation.LiquidityPoolID)
	if poolID == "" {
		poolID = strings.TrimSpace(fallbackPoolID)
	}
	if poolID == "" || strings.TrimSpace(operation.TransactionHash) == "" {
		return PiLiquidityMovementRow{}, false
	}
	return PiLiquidityMovementRow{
		PoolID:             poolID,
		OperationID:        strings.TrimSpace(operation.ID),
		Type:               movementType,
		TransactionHash:    strings.TrimSpace(operation.TransactionHash),
		SourceAccount:      strings.TrimSpace(operation.SourceAccount),
		Timestamp:          strings.TrimSpace(operation.CreatedAt),
		TargetAsset:        targetAsset,
		TargetAmount:       targetAmount,
		NativeAmount:       piLiquidityReserveAmount(amounts, "native"),
		Shares:             strings.TrimSpace(shares),
		VerificationStatus: "verified_horizon_operation",
		EvidenceSource:     piLiquidityHistorySource,
	}, true
}

func piLiquidityReserveAmount(amounts []piHorizonLiquidityAmount, asset string) string {
	for _, item := range amounts {
		if strings.TrimSpace(item.Asset) == asset {
			return strings.TrimSpace(item.Amount)
		}
	}
	return ""
}

func applyPiLiquidityHistoryToArm(arm SecurityRadarVerdict, observation PiLiquidityMovementObservation) SecurityRadarVerdict {
	if arm.Signals == nil {
		arm.Signals = map[string]any{}
	}
	arm.Signals["pi_liquidity_movement"] = observation
	arm.Signals["movement_verified"] = len(observation.Movements) > 0
	arm.Signals["movement_history_complete"] = observation.WindowComplete
	arm.Signals["deposit_count_observed"] = observation.DepositCount
	arm.Signals["withdraw_count_observed"] = observation.WithdrawCount
	arm.Signals["target_asset_deposited_observed"] = observation.TargetDeposited
	arm.Signals["target_asset_withdrawn_observed"] = observation.TargetWithdrawn
	arm.Signals["native_deposited_observed"] = observation.NativeDeposited
	arm.Signals["native_withdrawn_observed"] = observation.NativeWithdrawn
	arm.Signals["liquidity_movement_source"] = observation.Source
	arm.Signals["scope_note"] = "Historical liquidity movement is derived only from successful Horizon liquidity-pool deposit/withdraw operations in the bounded operation window."

	if len(observation.Movements) > 0 {
		arm.Signals["arm_evidence_available"] = true
		arm.Signals["evidence_status"] = "observed"
		arm.Evidence = append(arm.Evidence,
			fmt.Sprintf("Transaction-backed Pi liquidity movement observed: %d deposit(s), %d withdrawal(s).", observation.DepositCount, observation.WithdrawCount),
			fmt.Sprintf("Observed target-asset reserves added=%.7f withdrawn=%.7f; native reserves added=%.7f withdrawn=%.7f.", observation.TargetDeposited, observation.TargetWithdrawn, observation.NativeDeposited, observation.NativeWithdrawn),
		)
		for index, movement := range observation.Movements {
			if index >= 8 {
				arm.Evidence = append(arm.Evidence, fmt.Sprintf("%d additional liquidity movement row(s) remain in structured evidence.", len(observation.Movements)-index))
				break
			}
			arm.Evidence = append(arm.Evidence, fmt.Sprintf("%s tx=%s pool=%s target_amount=%s native_amount=%s source=%s timestamp=%s.", movement.Type, movement.TransactionHash, movement.PoolID, movement.TargetAmount, movement.NativeAmount, movement.SourceAccount, movement.Timestamp))
		}
	} else {
		arm.Evidence = append(arm.Evidence, "No successful target-asset liquidity deposit/withdraw operation was observed in the bounded pool-operation window; this is not proof of no historical movement.")
	}
	for _, limitation := range observation.Limitations {
		arm.Evidence = append(arm.Evidence, "Limitation: "+limitation)
	}
	return arm
}
