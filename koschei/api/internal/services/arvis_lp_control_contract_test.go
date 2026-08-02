package services

import "testing"

func TestLPControlUnsupportedPoolDoesNotCompleteCollectors(t *testing.T) {
	request := SecurityRadarRequest{Target: "Mint111", Network: "solana-mainnet", Mode: "manual_detail"}
	lp := LPControlEvidence{
		Available:   false,
		Status:      LPControlUnverified,
		ReasonCode:  "unsupported_pool_program",
		PoolAddress: "UnknownPool111",
		PoolProgram: "UnknownProgram111",
		Limitations: []string{"The pool program is not pinned."},
	}
	pool := lpControlPoolArm(request, lp, "2026-07-17T20:00:00Z")
	movement := lpControlLiquidityArm(request, lp, "2026-07-17T20:00:00Z")
	for _, arm := range []SecurityRadarVerdict{pool, movement} {
		if arm.Signed {
			t.Fatalf("unsupported pool produced signed completed arm: %#v", arm)
		}
		if got := arvisSignalString(arm.Signals, "execution_status"); got != ArvisExecutionInsufficient {
			t.Fatalf("module=%s status=%q arm=%#v", arm.ModuleID, got, arm)
		}
	}
}

func TestLPControlDecodedPositionPoolCompletesWithoutInventingLPToken(t *testing.T) {
	request := SecurityRadarRequest{Target: "Mint111", Network: "solana-mainnet", Mode: "manual_detail"}
	lp := LPControlEvidence{
		Available:   true,
		Status:      LPControlUnverified,
		ReasonCode:  "dlmm_position_ownership_not_enumerated",
		PoolAddress: "DLMM111", PoolProgram: "Program111", PoolType: "meteora_dlmm",
		ControlModel: "position_nft", PositionModel: "meteora_dlmm_position",
		TokenVault: "VaultX", QuoteVault: "VaultY", ReadSlot: 500,
		TokenReserve: 1000, QuoteReserve: 50,
		EvidenceKeys: []string{"pool:DLMM111@500"},
	}
	arm := lpControlPoolArm(request, lp, "2026-07-17T20:00:00Z")
	if !arm.Signed || arvisSignalString(arm.Signals, "execution_status") != ArvisExecutionCompleted {
		t.Fatalf("decoded pool did not complete: %#v", arm)
	}
	if value, _ := arm.Signals["lp_mint"].(string); value != "" {
		t.Fatalf("position pool invented LP mint %q", value)
	}
}
