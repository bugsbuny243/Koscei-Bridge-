package services

import "testing"

func TestCorrelatePumpPortalTradeTransactionVerifiesExactPumpBuy(t *testing.T) {
	mint := "MintPumpCorrelation11111111111111111111111111"
	trader := "TraderPumpCorrelation111111111111111111111"
	trade := LaunchTrade{Mint: mint, Trader: trader, Side: "buy", Slot: 77, Signature: "sig-buy", Source: "pumpportal"}
	tx := pumpTradeCorrelationTestTransaction(mint, trader, defaultPumpProgramID, 77, 0, 12)

	got := correlatePumpPortalTradeTransaction(trade, tx, mint)
	if got.VerificationStatus != "verified_correlated" {
		t.Fatalf("verification status = %q, want verified_correlated (%s)", got.VerificationStatus, got.ReasonCode)
	}
	if got.ReasonCode != "canonical_transaction_match" || got.Program != "pump.fun" {
		t.Fatalf("unexpected correlation evidence: %+v", got)
	}
}

func TestCorrelatePumpPortalTradeTransactionDoesNotUpgradeDirectionMismatch(t *testing.T) {
	mint := "MintPumpCorrelation22222222222222222222222222"
	trader := "TraderPumpCorrelation222222222222222222222"
	trade := LaunchTrade{Mint: mint, Trader: trader, Side: "sell", Slot: 88, Signature: "sig-side", Source: "pumpportal"}
	tx := pumpTradeCorrelationTestTransaction(mint, trader, defaultPumpProgramID, 88, 0, 5)

	got := correlatePumpPortalTradeTransaction(trade, tx, mint)
	if got.VerificationStatus == "verified_correlated" {
		t.Fatalf("direction mismatch was upgraded: %+v", got)
	}
	if got.ReasonCode != "trade_direction_mismatch" {
		t.Fatalf("reason = %q, want trade_direction_mismatch", got.ReasonCode)
	}
}

func TestCorrelatePumpPortalTradeTransactionDoesNotUpgradeSlotOrProgramMismatch(t *testing.T) {
	mint := "MintPumpCorrelation33333333333333333333333333"
	trader := "TraderPumpCorrelation333333333333333333333"
	trade := LaunchTrade{Mint: mint, Trader: trader, Side: "buy", Slot: 99, Signature: "sig-slot", Source: "pumpportal"}

	slotMismatch := pumpTradeCorrelationTestTransaction(mint, trader, defaultPumpProgramID, 100, 0, 5)
	got := correlatePumpPortalTradeTransaction(trade, slotMismatch, mint)
	if got.VerificationStatus == "verified_correlated" || got.ReasonCode != "slot_mismatch" {
		t.Fatalf("slot mismatch was not withheld: %+v", got)
	}

	programMismatch := pumpTradeCorrelationTestTransaction(mint, trader, "11111111111111111111111111111111", 99, 0, 5)
	got = correlatePumpPortalTradeTransaction(trade, programMismatch, mint)
	if got.VerificationStatus == "verified_correlated" || got.ReasonCode != "pump_program_not_observed" {
		t.Fatalf("program mismatch was not withheld: %+v", got)
	}
}

func TestPumpTradeCorrelationUnavailableRemainsObservedOnly(t *testing.T) {
	trade := LaunchTrade{Trader: "TraderObservedOnly", Side: "buy", Slot: 123, Signature: "sig-unavailable", Source: "pumpportal"}
	got := pumpTradeCorrelationUnavailable(trade)
	if got.VerificationStatus != "observed_unverified" || got.ReasonCode != "canonical_transaction_unavailable" {
		t.Fatalf("unavailable observation was upgraded: %+v", got)
	}
}

func pumpTradeCorrelationTestTransaction(mint, trader, program string, slot int64, pre, post float64) SolanaTransactionResult {
	balance := func(value float64) map[string]any {
		return map[string]any{
			"mint":          mint,
			"owner":         trader,
			"uiTokenAmount": map[string]any{"uiAmount": value},
		}
	}
	return SolanaTransactionResult{
		"slot": slot,
		"transaction": map[string]any{
			"message": map[string]any{
				"accountKeys": []any{trader, program},
			},
		},
		"meta": map[string]any{
			"preTokenBalances":  []any{balance(pre)},
			"postTokenBalances": []any{balance(post)},
		},
	}
}
