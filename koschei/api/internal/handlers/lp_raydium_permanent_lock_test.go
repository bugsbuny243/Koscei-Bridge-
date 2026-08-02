package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"koschei/api/internal/services"
)

func TestFinalizeRaydiumPermanentLPLockAggregatesOnlyPinnedCPMMCustody(t *testing.T) {
	lp := services.LPControlEvidence{
		Available:      true,
		Status:         services.LPControlVerifiedBurned,
		ReasonCode:     "burn_address_lp_observed",
		PoolProgram:    raydiumCPMMProgram,
		ControlModel:   "lp_token",
		LPSupply:       1000,
		BurnedSharePct: 10,
		LockerProgram:  raydiumLPLockProgram,
		LockerAccount:  "LockerPDAOne",
		ReadSlot:       12345,
		LargestLPHolders: []services.LPHolderEvidence{
			{TokenAccount: "LockedTokenA", OwnerWallet: "LockerPDAOne", Amount: 300, SharePct: 30, AccountOwner: raydiumLPLockProgram, Classification: "raydium_burn_and_earn"},
			{TokenAccount: "LockedTokenB", OwnerWallet: "LockerPDATwo", Amount: 200, SharePct: 20, AccountOwner: raydiumLPLockProgram, Classification: "raydium_burn_and_earn"},
			{TokenAccount: "SpoofedLabel", OwnerWallet: "OrdinaryWallet", Amount: 100, SharePct: 10, AccountOwner: "OrdinaryProgram", Classification: "raydium_burn_and_earn"},
		},
		Limitations: []string{unresolvedLockerLimitation, "Largest-account RPC is bounded."},
	}

	got := finalizeRaydiumPermanentLPLock(lp)
	if got.Status != services.LPControlVerifiedPermanentLocked || got.ReasonCode != "raydium_cpmm_burn_and_earn_permanent_lock_observed" {
		t.Fatalf("permanent lock status was not verified: %#v", got)
	}
	if got.LockedLPAmount != 500 || got.LockedLPSharePct != 50 {
		t.Fatalf("locked LP aggregate = amount %.8f share %.4f", got.LockedLPAmount, got.LockedLPSharePct)
	}
	if strings.Join(got.LockedLPTokenAccounts, ",") != "LockedTokenA,LockedTokenB" {
		t.Fatalf("locked token accounts = %v", got.LockedLPTokenAccounts)
	}
	if strings.Join(got.LockedLPAuthorityAccounts, ",") != "LockerPDAOne,LockerPDATwo" || got.LockerAccount != "" {
		t.Fatalf("locked authority accounts = %v singular=%q", got.LockedLPAuthorityAccounts, got.LockerAccount)
	}
	if got.BurnedSharePct != 10 {
		t.Fatalf("independent burn evidence was lost: %.4f", got.BurnedSharePct)
	}
	for _, limitation := range got.Limitations {
		if limitation == unresolvedLockerLimitation {
			t.Fatal("resolved permanent lock retained the unlock-unresolved limitation")
		}
	}
	if !containsStringValue(got.EvidenceKeys, "raydium_burn_and_earn_program:"+raydiumLPLockProgram) {
		t.Fatalf("program evidence key missing: %v", got.EvidenceKeys)
	}
}

func TestFinalizeRaydiumPermanentLPLockRejectsUnsupportedPoolModels(t *testing.T) {
	base := services.LPControlEvidence{
		Available:     true,
		Status:        services.LPControlUnverified,
		ReasonCode:    "locker_program_observed_unlock_unresolved",
		PoolProgram:   raydiumCPMMProgram,
		ControlModel:  "lp_token",
		LPSupply:      1000,
		LockerProgram: "UnpinnedProgram",
		LargestLPHolders: []services.LPHolderEvidence{{
			TokenAccount: "TokenA", OwnerWallet: "WalletA", Amount: 900, SharePct: 90,
			AccountOwner: "UnpinnedProgram", Classification: "raydium_burn_and_earn",
		}},
	}
	got := finalizeRaydiumPermanentLPLock(base)
	if got.Status != services.LPControlUnverified || got.LockedLPSharePct != 0 || len(got.LockedLPTokenAccounts) != 0 {
		t.Fatalf("unpinned program was treated as permanent custody: %#v", got)
	}

	base.LockerProgram = raydiumLPLockProgram
	base.LargestLPHolders[0].AccountOwner = raydiumLPLockProgram
	for _, unsupportedProgram := range []string{raydiumAMMV4Program, pumpSwapProgram} {
		base.PoolProgram = unsupportedProgram
		got = finalizeRaydiumPermanentLPLock(base)
		if got.Status != services.LPControlUnverified || got.LockedLPSharePct != 0 {
			t.Fatalf("unsupported pool program %s was upgraded by the CPMM lock rule: %#v", unsupportedProgram, got)
		}
	}
}

func TestFinalizeRaydiumPermanentLPLockWithholdsInconsistentSupply(t *testing.T) {
	lp := services.LPControlEvidence{
		Available: true, Status: services.LPControlUnverified, PoolProgram: raydiumCPMMProgram,
		ControlModel: "lp_token", LPSupply: 100, LockerProgram: raydiumLPLockProgram,
		LargestLPHolders: []services.LPHolderEvidence{{
			TokenAccount: "LockedToken", OwnerWallet: "LockerPDA", Amount: 101,
			AccountOwner: raydiumLPLockProgram, Classification: "raydium_burn_and_earn",
		}},
	}
	got := finalizeRaydiumPermanentLPLock(lp)
	if got.Status != services.LPControlUnverified || got.LockedLPSharePct != 0 {
		t.Fatalf("inconsistent holder/supply snapshots were verified: %#v", got)
	}
	if !containsSubstringValue(got.Limitations, "exceeded the observed LP mint supply") {
		t.Fatalf("inconsistent supply limitation missing: %v", got.Limitations)
	}
}

func TestPopulateDecodedLPControlResolvesBurnAndEarnAuthorityProgram(t *testing.T) {
	balanceCalls := 0
	rpc := func(_ context.Context, _ string, method string, params any, out any) error {
		switch method {
		case "getTokenAccountBalance":
			balanceCalls++
			response := out.(*rpcTokenBalanceResponse)
			response.Context.Slot = 500
			if balanceCalls == 1 {
				response.Value.UIAmountString = "100000"
			} else {
				response.Value.UIAmountString = "5000"
			}
		case "getTokenSupply":
			response := out.(*rpcTokenSupplyResponse)
			response.Context.Slot = 501
			response.Value.UIAmountString = "1000"
		case "getTokenLargestAccounts":
			response := out.(*rpcLargestAccountsResponse)
			response.Context.Slot = 501
			response.Value = []rpcLargestAccount{
				{Address: "LockedLPTokenAccount", rpcTokenAmount: rpcTokenAmount{UIAmountString: "600"}},
				{Address: "OrdinaryLPTokenAccount", rpcTokenAmount: rpcTokenAmount{UIAmountString: "100"}},
			}
		case "getMultipleAccounts":
			arguments, ok := params.([]any)
			if !ok || len(arguments) == 0 {
				return errors.New("getMultipleAccounts params missing")
			}
			addresses, ok := arguments[0].([]string)
			if !ok {
				return errors.New("getMultipleAccounts addresses malformed")
			}
			response := out.(*struct {
				Value []json.RawMessage `json:"value"`
			})
			response.Value = make([]json.RawMessage, 0, len(addresses))
			for _, address := range addresses {
				switch address {
				case "LockedLPTokenAccount":
					response.Value = append(response.Value, json.RawMessage(`{"data":{"parsed":{"info":{"owner":"RaydiumLockPDA"}}}}`))
				case "OrdinaryLPTokenAccount":
					response.Value = append(response.Value, json.RawMessage(`{"data":{"parsed":{"info":{"owner":"OrdinaryWallet"}}}}`))
				case "RaydiumLockPDA":
					response.Value = append(response.Value, json.RawMessage(`{"owner":"`+raydiumLPLockProgram+`"}`))
				case "OrdinaryWallet":
					response.Value = append(response.Value, json.RawMessage(`{"owner":"11111111111111111111111111111111"}`))
				default:
					response.Value = append(response.Value, json.RawMessage(`null`))
				}
			}
		default:
			return errors.New("unexpected RPC method: " + method)
		}
		return nil
	}

	collected := populateDecodedLPControl(context.Background(), rpc, "solana-mainnet", "", services.LPControlEvidence{
		PoolAddress: "RaydiumPool", PoolProgram: raydiumCPMMProgram, PoolType: "raydium_cpmm",
		ControlModel: "lp_token", PositionModel: "fungible_lp_token", LPMint: "LPMint",
		TokenVault: "TokenVault", QuoteVault: "QuoteVault", LargestLPHolders: []services.LPHolderEvidence{},
		EvidenceKeys: []string{}, Limitations: []string{},
	})
	if collected.LockerProgram != raydiumLPLockProgram || collected.LockerAccount != "RaydiumLockPDA" {
		t.Fatalf("pinned locker authority was not resolved: %#v", collected)
	}
	if collected.ReasonCode != "locker_program_observed_unlock_unresolved" {
		t.Fatalf("collector prematurely claimed permanent lock: %#v", collected)
	}

	got := finalizeRaydiumPermanentLPLock(collected)
	if got.Status != services.LPControlVerifiedPermanentLocked || got.LockedLPAmount != 600 || got.LockedLPSharePct != 60 {
		t.Fatalf("resolved Burn & Earn custody was not finalized: %#v", got)
	}
	if len(got.LockedLPTokenAccounts) != 1 || got.LockedLPTokenAccounts[0] != "LockedLPTokenAccount" {
		t.Fatalf("locked token accounts = %v", got.LockedLPTokenAccounts)
	}
	if len(got.LockedLPAuthorityAccounts) != 1 || got.LockedLPAuthorityAccounts[0] != "RaydiumLockPDA" || got.LockerAccount != "RaydiumLockPDA" {
		t.Fatalf("locked authority evidence = %v singular=%q", got.LockedLPAuthorityAccounts, got.LockerAccount)
	}
}

func containsStringValue(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func containsSubstringValue(values []string, expected string) bool {
	for _, value := range values {
		if strings.Contains(value, expected) {
			return true
		}
	}
	return false
}
