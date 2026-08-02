package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestApplyLPControlEvidenceReferencesCarriesMovementSignatureAndSlot(t *testing.T) {
	refs := map[string]unifiedEvidenceReference{"liquidity": {}, "liq-move": {}}
	lp := services.LPControlEvidence{
		PoolAddress: "Pool111", PoolProgram: pumpSwapProgram, PoolCreator: "Creator111",
		TokenMint: "Mint111", QuoteMint: "Quote111", TokenVault: "TokenVault111", QuoteVault: "QuoteVault111",
		ReadSlot: 1400, EvidenceKeys: []string{"pool:Pool111@1400"},
		LiquidityMovements: []services.LiquidityMovementEvidence{{
			Kind: "remove_liquidity", Signature: "RemoveSig111", Slot: 1401,
			ActorWallet: "Actor111", PoolAddress: "Pool111", Program: pumpSwapProgram,
			EvidenceKey: "liquidity_movement:remove_liquidity:RemoveSig111:1401",
		}},
	}
	refs = applyLPControlEvidenceReferences(refs, lp)
	for _, rowID := range []string{"liquidity", "liq-move"} {
		ref := refs[rowID]
		if !containsString(ref.Signatures, "RemoveSig111") || !containsInt64(ref.Slots, 1401) {
			t.Fatalf("row=%s ref=%#v", rowID, ref)
		}
		if !containsString(ref.Wallets, "Actor111") || !containsString(ref.Accounts, "Pool111") {
			t.Fatalf("row=%s ref=%#v", rowID, ref)
		}
	}
}

func containsString(values []string, target string) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}

func containsInt64(values []int64, target int64) bool {
	for _, value := range values {
		if value == target {
			return true
		}
	}
	return false
}
