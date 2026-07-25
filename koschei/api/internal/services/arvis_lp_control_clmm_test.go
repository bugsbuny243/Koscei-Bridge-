package services

import (
	"strings"
	"testing"
)

func TestLPControlPoolArmExposesCLMMPositionsWithoutPercentage(t *testing.T) {
	lp := LPControlEvidence{
		Available: true,
		Status: LPControlVerifiedPermanentLocked,
		ReasonCode: "raydium_clmm_burn_and_earn_positions_verified",
		PoolAddress: "CLMMPool",
		PoolProgram: "CAMMCzo5YL8w4VFF8KVHrK22GGUsp5VTaW7grrKgrWqK",
		PoolType: "raydium_clmm",
		ControlModel: "position_nft",
		PositionModel: "raydium_clmm_position_nft",
		TokenVault: "TokenVault",
		QuoteVault: "QuoteVault",
		ReadSlot: 777,
		PoolLiquidityRaw: "123456",
		LockedPositionCount: 1,
		LockedPositionLiquidityRaw: "98765",
		PositionEnumerationStatus: "verified_complete_bounded_filter",
		PositionEnumerationLimit: 200,
		LockedPositions: []CLMMLockedPositionEvidence{{
			LockedPositionAccount: "LockState",
			PositionOwner: "OriginalOwner",
			PositionAccount: "PersonalPosition",
			PositionNFTMint: "PositionNFT",
			LockedNFTAccount: "CustodyTokenAccount",
			CustodyAuthority: "ProgramAuthority",
			FeeNFTMint: "FeeNFT",
			TickLowerIndex: -120,
			TickUpperIndex: 240,
			LiquidityRaw: "98765",
			VerificationStatus: "VERIFIED",
		}},
		LargestLPHolders: []LPHolderEvidence{},
		LiquidityMovements: []LiquidityMovementEvidence{},
		EvidenceKeys: []string{"raydium_clmm_lock:LockState@777"},
		Limitations: []string{"No locked percentage is calculated."},
	}
	arm := lpControlPoolArm(SecurityRadarRequest{}, lp, "2026-07-22T00:00:00Z")
	if arm.Signals["evidence_status"] != "verified" || arm.Signals["locked_position_count"] != 1 {
		t.Fatalf("CLMM verified signals missing: %#v", arm.Signals)
	}
	if arm.Signals["locked_position_liquidity_raw"] != "98765" || arm.Signals["position_enumeration_status"] != "verified_complete_bounded_filter" {
		t.Fatalf("CLMM enumeration signals missing: %#v", arm.Signals)
	}
	if arm.Signals["permanent_locked_share_pct"] != float64(0) || arm.Signals["locked_lp_share_pct"] != float64(0) {
		t.Fatalf("CLMM arm invented a lock percentage: %#v", arm.Signals)
	}
	positions, ok := arm.Signals["locked_positions"].([]CLMMLockedPositionEvidence)
	if !ok || len(positions) != 1 || positions[0].PositionNFTMint != "PositionNFT" {
		t.Fatalf("CLMM positions missing from signals: %#v", arm.Signals["locked_positions"])
	}
	evidence := strings.Join(arm.Evidence, "\n")
	if !strings.Contains(evidence, "1 VERIFIED Burn & Earn positions") || !strings.Contains(evidence, "position NFT mint PositionNFT") {
		t.Fatalf("CLMM human evidence missing: %s", evidence)
	}
	if strings.Contains(evidence, "98765.0000%") {
		t.Fatalf("CLMM liquidity was rendered as a percentage: %s", evidence)
	}
}
