package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestFinalizeRaydiumPermanentLPLockUsesHolderSpecificProgramEvidence(t *testing.T) {
	lp := services.LPControlEvidence{
		Available:     true,
		Status:        services.LPControlUnverified,
		PoolProgram:   raydiumCPMMProgram,
		ControlModel:  "lp_token",
		LPSupply:      1000,
		LockerProgram: streamflowProgram,
		LockerAccount: "UnrelatedStreamflowPDA",
		LargestLPHolders: []services.LPHolderEvidence{{
			TokenAccount:   "LockedToken",
			OwnerWallet:    "RaydiumBurnAndEarnPDA",
			Amount:         400,
			SharePct:       40,
			AccountOwner:   raydiumLPLockProgram,
			Classification: "raydium_burn_and_earn",
		}},
	}
	got := finalizeRaydiumPermanentLPLock(lp)
	if got.Status != services.LPControlVerifiedPermanentLocked || got.LockedLPSharePct != 40 {
		t.Fatalf("holder-specific Burn & Earn custody was shadowed by another locker: %#v", got)
	}
	if got.LockerProgram != raydiumLPLockProgram || got.LockerAccount != "RaydiumBurnAndEarnPDA" {
		t.Fatalf("resolved locker identity = program %q account %q", got.LockerProgram, got.LockerAccount)
	}
}

func TestFinalizeRaydiumPermanentLPLockWithholdsCombinedShareOverSupply(t *testing.T) {
	lp := services.LPControlEvidence{
		Available:      true,
		Status:         services.LPControlVerifiedBurned,
		PoolProgram:    raydiumCPMMProgram,
		ControlModel:   "lp_token",
		LPSupply:       1000,
		BurnedSharePct: 20,
		LargestLPHolders: []services.LPHolderEvidence{{
			TokenAccount:   "LockedToken",
			OwnerWallet:    "RaydiumBurnAndEarnPDA",
			Amount:         810,
			SharePct:       81,
			AccountOwner:   raydiumLPLockProgram,
			Classification: "raydium_burn_and_earn",
		}},
	}
	got := finalizeRaydiumPermanentLPLock(lp)
	if got.Status == services.LPControlVerifiedPermanentLocked || got.LockedLPSharePct != 0 {
		t.Fatalf("inconsistent combined burn/lock shares were verified: %#v", got)
	}
	if !containsSubstringValue(got.Limitations, "exceeded 100%") {
		t.Fatalf("combined-share inconsistency limitation missing: %v", got.Limitations)
	}
}
