package handlers

import (
	"context"
	"strings"
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestUnifiedLiveEvidenceDeadlineKeepsPartialLimitation(t *testing.T) {
	t.Setenv("SOLANA_RPC_URL", "http://127.0.0.1:1")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	report := (&Handler{}).collectUnifiedTokenLiveEvidence(ctx, holderIntelligenceCoreResult{
		Request: services.SecurityRadarRequest{Target: "Mint111"}, SourceContext: map[string]any{"creator_wallet": "Creator111"},
	})
	if report.Status != "partial_timeout" {
		t.Fatalf("status = %q, want partial_timeout", report.Status)
	}
	if len(report.Limitations) == 0 || !strings.Contains(report.Limitations[0], "ended before every wallet target completed") {
		t.Fatalf("limitations = %#v", report.Limitations)
	}
}

func unifiedLiveTestTransaction(wallet, counterparty, mint string, walletPre, walletPost, counterpartyPre, counterpartyPost float64, instructionType string) services.SolanaTransactionResult {
	balances := func(walletAmount, counterpartyAmount float64) []any {
		return []any{
			map[string]any{"mint": mint, "owner": wallet, "uiTokenAmount": map[string]any{"uiAmount": walletAmount}},
			map[string]any{"mint": mint, "owner": counterparty, "uiTokenAmount": map[string]any{"uiAmount": counterpartyAmount}},
		}
	}
	return services.SolanaTransactionResult{
		"blockTime": float64(1_752_739_200),
		"meta": map[string]any{
			"err":               nil,
			"preTokenBalances":  balances(walletPre, counterpartyPre),
			"postTokenBalances": balances(walletPost, counterpartyPost),
			"logMessages":       []any{"Program log: Instruction: " + instructionType},
			"innerInstructions": []any{},
		},
		"transaction": map[string]any{"message": map[string]any{
			"accountKeys":  []any{map[string]any{"pubkey": wallet, "signer": true}},
			"instructions": []any{map[string]any{"parsed": map[string]any{"type": instructionType, "info": map[string]any{"mint": mint}}}},
		}},
	}
}

func TestParseUnifiedLiveTransactionClassifiesSell(t *testing.T) {
	mint := "Mint111"
	wallet := "Owner111"
	counterparty := "Pool111"
	tx := unifiedLiveTestTransaction(wallet, counterparty, mint, 100, 60, 0, 40, "swap")
	blockTime := int64(1_752_739_200)
	row, ok := parseUnifiedLiveTransaction(mint, unifiedLiveWalletTarget{Wallet: wallet, Role: "risk_bearing_holder"}, services.SolanaSignatureInfo{
		Signature: "SigSell111", Slot: 123, BlockTime: &blockTime,
	}, tx)
	if !ok {
		t.Fatal("sell transaction was not returned")
	}
	if row.Direction != "sell" || row.TokenDelta != -40 || !row.SwapRelated {
		t.Fatalf("row=%#v", row)
	}
	if len(row.Counterparties) != 1 || row.Counterparties[0] != counterparty {
		t.Fatalf("counterparties=%v", row.Counterparties)
	}
	if row.EvidenceKey != "SigSell111:Owner111:sell" || row.BlockTime == "" {
		t.Fatalf("evidence=%q block=%q", row.EvidenceKey, row.BlockTime)
	}
}

func TestParseUnifiedLiveTransactionSeparatesTransferFromSell(t *testing.T) {
	mint := "Mint111"
	wallet := "Creator111"
	tx := unifiedLiveTestTransaction(wallet, "Recipient111", mint, 25, 10, 0, 15, "transferChecked")
	row, ok := parseUnifiedLiveTransaction(mint, unifiedLiveWalletTarget{Wallet: wallet, Role: "creator_source_observed"}, services.SolanaSignatureInfo{Signature: "SigTransfer111", Slot: 124}, tx)
	if !ok {
		t.Fatal("transfer transaction was not returned")
	}
	if row.Direction != "transfer_out" || row.SwapRelated || row.TokenDelta != -15 {
		t.Fatalf("row=%#v", row)
	}
}

func TestParseUnifiedLiveTransactionIgnoresUnchangedWallet(t *testing.T) {
	tx := unifiedLiveTestTransaction("Owner111", "Other111", "Mint111", 10, 10, 4, 4, "transferChecked")
	if _, ok := parseUnifiedLiveTransaction("Mint111", unifiedLiveWalletTarget{Wallet: "Owner111", Role: "risk_bearing_holder"}, services.SolanaSignatureInfo{Signature: "NoDelta"}, tx); ok {
		t.Fatal("unchanged wallet produced a transaction evidence row")
	}
}

func TestUnifiedLiveWalletTargetsAreResolvedAndBounded(t *testing.T) {
	holder := services.HolderIntelligence{Rows: []services.HolderIntelligenceRow{
		{OwnerWallet: "Creator111", OwnerResolved: true, RiskBearing: true},
		{OwnerWallet: "Owner222", OwnerResolved: true, RiskBearing: true},
		{OwnerWallet: "Infra333", OwnerResolved: true, RiskBearing: true, ExcludedFromHolderRisk: true},
		{OwnerWallet: "Owner444", OwnerResolved: true, RiskBearing: true},
		{OwnerWallet: "Owner555", OwnerResolved: true, RiskBearing: true},
		{OwnerWallet: "Owner666", OwnerResolved: true, RiskBearing: true},
	}}
	targets := unifiedLiveWalletTargets(holder, "Creator111", unifiedLaunchSignerObservation{})
	if len(targets) != 4 {
		t.Fatalf("targets=%#v", targets)
	}
	if targets[0].Role != "creator_source_observed" || targets[1].Wallet != "Owner222" || targets[3].Wallet != "Owner555" {
		t.Fatalf("targets=%#v", targets)
	}
}

func TestUnifiedLiveEvidenceModeBoundary(t *testing.T) {
	for _, mode := range []string{"customer_token_scan", "manual_detail", "owner_unified_manual_scan"} {
		if !unifiedLiveEvidenceAllowed(mode) {
			t.Fatalf("full mode %q disabled", mode)
		}
	}
	for _, mode := range []string{"", "safe_check", "arvis_preflight", "stored_only_projection"} {
		if unifiedLiveEvidenceAllowed(mode) {
			t.Fatalf("bounded mode %q enabled live evidence", mode)
		}
	}
}

func TestSummarizeUnifiedTransactionEvidence(t *testing.T) {
	now := time.Now().UTC()
	rows := []unifiedTransactionEvidence{
		{Signature: "A", Trader: "Wallet1", Direction: "buy", BlockTime: &now},
		{Signature: "B", Trader: "Wallet1", Direction: "sell", BlockTime: &now},
		{Signature: "C", Trader: "Wallet2", Direction: "transfer_in", BlockTime: &now},
	}
	summary := summarizeUnifiedTransactionEvidence(rows)
	if summary["trade_count"] != int64(3) || summary["buy_count"] != int64(1) || summary["sell_count"] != int64(1) {
		t.Fatalf("summary=%#v", summary)
	}
	if summary["unique_trader_count"] != int64(2) || summary["round_trip_wallet_count"] != int64(1) {
		t.Fatalf("summary=%#v", summary)
	}
}
