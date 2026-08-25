package services

import (
	"strings"
	"testing"
)

func TestPiLiquidityMovementRowMapsDepositEvidence(t *testing.T) {
	target := "ABC:GISSUER"
	operation := piHorizonLiquidityOperation{
		ID:              "op-1",
		Type:            "liquidity_pool_deposit",
		TransactionHash: "tx-deposit",
		SourceAccount:   "GDEPOSITOR",
		CreatedAt:       "2026-08-25T07:00:00Z",
		LiquidityPoolID: "pool-1",
		ReservesDeposited: []piHorizonLiquidityAmount{
			{Asset: "native", Amount: "25.5000000"},
			{Asset: target, Amount: "100.0000000"},
		},
		SharesReceived: "12.5000000",
	}
	row, ok := piLiquidityMovementRow(operation, "", target)
	if !ok {
		t.Fatal("expected deposit movement")
	}
	if row.Type != "liquidity_pool_deposit" || row.TargetAmount != "100.0000000" || row.NativeAmount != "25.5000000" || row.Shares != "12.5000000" {
		t.Fatalf("unexpected deposit row: %#v", row)
	}
	if row.TransactionHash != "tx-deposit" || row.VerificationStatus != "verified_horizon_operation" {
		t.Fatalf("missing transaction verification fields: %#v", row)
	}
}

func TestPiLiquidityMovementRowMapsWithdrawEvidence(t *testing.T) {
	target := "ABC:GISSUER"
	operation := piHorizonLiquidityOperation{
		ID:              "op-2",
		Type:            "liquidity_pool_withdraw",
		TransactionHash: "tx-withdraw",
		SourceAccount:   "GWITHDRAWER",
		CreatedAt:       "2026-08-25T07:05:00Z",
		ReservesReceived: []piHorizonLiquidityAmount{
			{Asset: target, Amount: "40.0000000"},
			{Asset: "native", Amount: "10.2500000"},
		},
		Shares: "5.0000000",
	}
	row, ok := piLiquidityMovementRow(operation, "fallback-pool", target)
	if !ok {
		t.Fatal("expected withdrawal movement")
	}
	if row.PoolID != "fallback-pool" || row.TargetAmount != "40.0000000" || row.NativeAmount != "10.2500000" || row.Shares != "5.0000000" {
		t.Fatalf("unexpected withdrawal row: %#v", row)
	}
}

func TestPiLiquidityMovementRowRejectsUnrelatedOrUnverifiableOperations(t *testing.T) {
	target := "ABC:GISSUER"
	cases := []piHorizonLiquidityOperation{
		{Type: "payment", TransactionHash: "tx", LiquidityPoolID: "pool"},
		{Type: "liquidity_pool_deposit", TransactionHash: "tx", LiquidityPoolID: "pool", ReservesDeposited: []piHorizonLiquidityAmount{{Asset: "OTHER:GISSUER", Amount: "1"}}},
		{Type: "liquidity_pool_withdraw", LiquidityPoolID: "pool", ReservesReceived: []piHorizonLiquidityAmount{{Asset: target, Amount: "1"}}},
	}
	for index, operation := range cases {
		if row, ok := piLiquidityMovementRow(operation, "", target); ok {
			t.Fatalf("case %d unexpectedly mapped: %#v", index, row)
		}
	}
}

func TestApplyPiLiquidityHistoryToArmPreservesBoundedEvidenceSemantics(t *testing.T) {
	arm := SecurityRadarVerdict{
		ModuleID: ModuleLiquidityMovement,
		Signals:  map[string]any{"evidence_status": "observed"},
		Evidence: []string{"Current Pi liquidity-pool state observed."},
	}
	observation := PiLiquidityMovementObservation{
		Status:          "partial_observation",
		EvidenceStatus:  "observed",
		Source:          piLiquidityHistorySource,
		Asset:           "ABC:GISSUER",
		PoolsDiscovered: 1,
		PoolsQueried:    1,
		WindowComplete:  false,
		DepositCount:    1,
		WithdrawCount:   1,
		TargetDeposited: 100,
		TargetWithdrawn: 40,
		NativeDeposited: 25.5,
		NativeWithdrawn: 10.25,
		Movements: []PiLiquidityMovementRow{
			{PoolID: "pool", Type: "liquidity_pool_deposit", TransactionHash: "tx1", TargetAmount: "100", NativeAmount: "25.5", SourceAccount: "G1", Timestamp: "t1"},
			{PoolID: "pool", Type: "liquidity_pool_withdraw", TransactionHash: "tx2", TargetAmount: "40", NativeAmount: "10.25", SourceAccount: "G2", Timestamp: "t2"},
		},
		Limitations: []string{"Operation history is bounded."},
	}
	got := applyPiLiquidityHistoryToArm(arm, observation)
	if got.Signals["movement_verified"] != true {
		t.Fatalf("movement must be verified: %#v", got.Signals)
	}
	if got.Signals["movement_history_complete"] != false {
		t.Fatalf("bounded history must remain incomplete: %#v", got.Signals)
	}
	joined := strings.Join(got.Evidence, " ")
	if !strings.Contains(joined, "tx=tx1") || !strings.Contains(joined, "tx=tx2") || !strings.Contains(joined, "Limitation:") {
		t.Fatalf("expected transaction-backed evidence and limitation: %s", joined)
	}
}

func TestApplyPiLiquidityHistoryDoesNotTreatNoMovementAsSafe(t *testing.T) {
	arm := SecurityRadarVerdict{ModuleID: ModuleLiquidityMovement, Signals: map[string]any{}}
	observation := PiLiquidityMovementObservation{
		Status:         "no_movement_observed",
		EvidenceStatus: "observed",
		Source:         piLiquidityHistorySource,
		Asset:          "ABC:GISSUER",
		WindowComplete: false,
		Movements:      []PiLiquidityMovementRow{},
	}
	got := applyPiLiquidityHistoryToArm(arm, observation)
	joined := strings.ToLower(strings.Join(got.Evidence, " "))
	if !strings.Contains(joined, "not proof") {
		t.Fatalf("missing no-safe limitation: %s", joined)
	}
	if got.Signals["movement_verified"] != false {
		t.Fatalf("movement_verified should be false: %#v", got.Signals)
	}
}
