package services

import "testing"

func TestHolderClusterFlowSummarizesCommonExitAndCircularTransfers(t *testing.T) {
	wallets := []HolderClusterWallet{
		{
			Wallet: "WalletA", HolderPercentage: 10,
			FlowObservations: []HolderClusterFlowObservation{
				{SourceWallet: "WalletA", Destination: "ExitOwner", Kind: "external_token_recipient", Amount: 4, Signature: "sig-a-exit"},
				{SourceWallet: "WalletA", Destination: "WalletB", Kind: "holder_to_holder", Amount: 1, Signature: "sig-a-b"},
			},
		},
		{
			Wallet: "WalletB", HolderPercentage: 12,
			FlowObservations: []HolderClusterFlowObservation{
				{SourceWallet: "WalletB", Destination: "ExitOwner", Kind: "external_token_recipient", Amount: 5, Signature: "sig-b-exit"},
				{SourceWallet: "WalletB", Destination: "WalletA", Kind: "holder_to_holder", Amount: 1, Signature: "sig-b-a"},
			},
		},
		{Wallet: "WalletC", HolderPercentage: 8, FlowObservations: []HolderClusterFlowObservation{}},
	}

	flow := summarizeHolderClusterFlow(wallets)
	if !flow.Available {
		t.Fatalf("expected available flow analysis: %#v", flow)
	}
	if flow.CommonExitGroupCount != 1 || flow.LargestCommonExitGroup != 2 {
		t.Fatalf("unexpected common exit groups: %#v", flow.CommonExitGroups)
	}
	if flow.InternalTransferCount != 2 {
		t.Fatalf("internal transfer count = %d", flow.InternalTransferCount)
	}
	if flow.CircularWalletCount != 2 {
		t.Fatalf("circular wallet count = %d (%v)", flow.CircularWalletCount, flow.CircularWallets)
	}
	if flow.LinkedHolderPercentage != 22 {
		t.Fatalf("linked holder percentage = %f", flow.LinkedHolderPercentage)
	}
	if flow.RiskContribution < 30 || flow.Confidence != "high" {
		t.Fatalf("unexpected flow risk/confidence: %d %s", flow.RiskContribution, flow.Confidence)
	}
}

func TestHolderClusterFlowDoesNotScoreSharedDEXProgramAsCommonExit(t *testing.T) {
	wallets := []HolderClusterWallet{
		{Wallet: "WalletA", HolderPercentage: 10, FlowObservations: []HolderClusterFlowObservation{{SourceWallet: "WalletA", Destination: pumpLiquidityProgramID, Kind: "dex_program_exit_context", Amount: 2, Signature: "sig-a", ProgramIDs: []string{pumpLiquidityProgramID}}}},
		{Wallet: "WalletB", HolderPercentage: 12, FlowObservations: []HolderClusterFlowObservation{{SourceWallet: "WalletB", Destination: pumpLiquidityProgramID, Kind: "dex_program_exit_context", Amount: 3, Signature: "sig-b", ProgramIDs: []string{pumpLiquidityProgramID}}}},
	}
	flow := summarizeHolderClusterFlow(wallets)
	if !flow.Available {
		t.Fatal("expected route context to be available")
	}
	if flow.CommonExitGroupCount != 0 || flow.LargestCommonExitGroup != 0 {
		t.Fatalf("DEX program identity must not be common-exit evidence: %#v", flow.CommonExitGroups)
	}
	if flow.RiskContribution != 0 {
		t.Fatalf("program-only route context must not increase risk: %d", flow.RiskContribution)
	}
}

func TestHolderClusterFlowDoesNotScoreSharedDEXRecipientOwner(t *testing.T) {
	wallets := []HolderClusterWallet{
		{Wallet: "WalletA", HolderPercentage: 10, FlowObservations: []HolderClusterFlowObservation{{SourceWallet: "WalletA", Destination: "PoolAuthority", Kind: "external_token_recipient", Amount: 2, Signature: "sig-a", ProgramIDs: []string{pumpLiquidityProgramID}}}},
		{Wallet: "WalletB", HolderPercentage: 12, FlowObservations: []HolderClusterFlowObservation{{SourceWallet: "WalletB", Destination: "PoolAuthority", Kind: "external_token_recipient", Amount: 3, Signature: "sig-b", ProgramIDs: []string{pumpLiquidityProgramID}}}},
	}
	flow := summarizeHolderClusterFlow(wallets)
	if flow.CommonExitGroupCount != 0 || flow.RiskContribution != 0 {
		t.Fatalf("shared DEX recipient owner must remain route context only: %#v", flow)
	}
}

func TestHolderClusterTokenOwnerDeltas(t *testing.T) {
	tx := map[string]any{
		"meta": map[string]any{
			"preTokenBalances": []any{
				map[string]any{"mint": "Mint", "owner": "WalletA", "uiTokenAmount": map[string]any{"uiAmountString": "10"}},
				map[string]any{"mint": "Mint", "owner": "WalletB", "uiTokenAmount": map[string]any{"uiAmountString": "2"}},
			},
			"postTokenBalances": []any{
				map[string]any{"mint": "Mint", "owner": "WalletA", "uiTokenAmount": map[string]any{"uiAmountString": "6"}},
				map[string]any{"mint": "Mint", "owner": "WalletB", "uiTokenAmount": map[string]any{"uiAmountString": "6"}},
			},
		},
	}
	deltas := holderClusterTokenOwnerDeltas(tx, "Mint")
	if deltas["WalletA"] != -4 || deltas["WalletB"] != 4 {
		t.Fatalf("unexpected deltas: %#v", deltas)
	}
}

func TestObserveHolderClusterWalletFlowPreservesTokenAccountsAndDecimals(t *testing.T) {
	tx := map[string]any{
		"slot": int64(321),
		"transaction": map[string]any{"message": map[string]any{
			"accountKeys": []any{
				map[string]any{"pubkey": "SourceATA"},
				map[string]any{"pubkey": "DestinationATA"},
				map[string]any{"pubkey": "WalletA"},
			},
			"instructions": []any{map[string]any{
				"program":   "spl-token",
				"programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
				"parsed": map[string]any{"type": "transferChecked", "info": map[string]any{
					"source": "SourceATA", "destination": "DestinationATA", "authority": "WalletA", "mint": "Mint",
					"tokenAmount": map[string]any{"amount": "4000000", "decimals": float64(6), "uiAmount": 4.0},
				}},
			}},
		}},
		"meta": map[string]any{
			"preTokenBalances": []any{
				map[string]any{"accountIndex": float64(0), "mint": "Mint", "owner": "WalletA", "uiTokenAmount": map[string]any{"amount": "10000000", "decimals": float64(6), "uiAmountString": "10"}},
				map[string]any{"accountIndex": float64(1), "mint": "Mint", "owner": "WalletB", "uiTokenAmount": map[string]any{"amount": "2000000", "decimals": float64(6), "uiAmountString": "2"}},
			},
			"postTokenBalances": []any{
				map[string]any{"accountIndex": float64(0), "mint": "Mint", "owner": "WalletA", "uiTokenAmount": map[string]any{"amount": "6000000", "decimals": float64(6), "uiAmountString": "6"}},
				map[string]any{"accountIndex": float64(1), "mint": "Mint", "owner": "WalletB", "uiTokenAmount": map[string]any{"amount": "6000000", "decimals": float64(6), "uiAmountString": "6"}},
			},
			"innerInstructions": []any{},
		},
	}
	observations := observeHolderClusterWalletFlow(tx, "sig-transfer", "Mint", "WalletA", map[string]bool{"WalletA": true, "WalletB": true})
	if len(observations) != 1 {
		t.Fatalf("observations=%d %#v", len(observations), observations)
	}
	observation := observations[0]
	if observation.SourceTokenAccount != "SourceATA" || observation.DestinationTokenAccount != "DestinationATA" {
		t.Fatalf("token accounts not preserved: %#v", observation)
	}
	if observation.Mint != "Mint" || observation.Decimals == nil || *observation.Decimals != 6 {
		t.Fatalf("token metadata not preserved: %#v", observation)
	}
	if observation.Destination != "WalletB" || observation.Kind != "holder_to_holder" || observation.Direction != "outbound" || observation.Amount != 4 {
		t.Fatalf("unexpected flow observation: %#v", observation)
	}
}

func TestObserveHolderClusterWalletFlowPreservesInboundContext(t *testing.T) {
	tx := map[string]any{
		"slot": int64(654),
		"transaction": map[string]any{"message": map[string]any{
			"accountKeys": []any{map[string]any{"pubkey": "CEXATA"}, map[string]any{"pubkey": "HolderATA"}, map[string]any{"pubkey": "CEXWallet"}},
			"instructions": []any{map[string]any{
				"program": "spl-token", "programId": "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA",
				"parsed": map[string]any{"type": "transferChecked", "info": map[string]any{
					"source": "CEXATA", "destination": "HolderATA", "authority": "CEXWallet", "mint": "Mint",
					"tokenAmount": map[string]any{"amount": "4000000", "decimals": float64(6), "uiAmount": 4.0},
				}},
			}},
		}},
		"meta": map[string]any{
			"preTokenBalances": []any{
				map[string]any{"accountIndex": float64(0), "mint": "Mint", "owner": "CEXWallet", "uiTokenAmount": map[string]any{"decimals": float64(6), "uiAmountString": "10"}},
				map[string]any{"accountIndex": float64(1), "mint": "Mint", "owner": "WalletA", "uiTokenAmount": map[string]any{"decimals": float64(6), "uiAmountString": "2"}},
			},
			"postTokenBalances": []any{
				map[string]any{"accountIndex": float64(0), "mint": "Mint", "owner": "CEXWallet", "uiTokenAmount": map[string]any{"decimals": float64(6), "uiAmountString": "6"}},
				map[string]any{"accountIndex": float64(1), "mint": "Mint", "owner": "WalletA", "uiTokenAmount": map[string]any{"decimals": float64(6), "uiAmountString": "6"}},
			},
			"innerInstructions": []any{},
		},
	}
	observations := observeHolderClusterWalletFlow(tx, "sig-inbound", "Mint", "WalletA", map[string]bool{"WalletA": true})
	if len(observations) != 1 {
		t.Fatalf("inbound observations=%d %#v", len(observations), observations)
	}
	observation := observations[0]
	if observation.SourceWallet != "CEXWallet" || observation.Destination != "WalletA" || observation.Direction != "inbound" {
		t.Fatalf("inbound direction not preserved: %#v", observation)
	}
	if observation.SourceTokenAccount != "CEXATA" || observation.DestinationTokenAccount != "HolderATA" || observation.Amount != 4 {
		t.Fatalf("inbound token evidence not preserved: %#v", observation)
	}
}

func TestHolderClusterFlowCountsCEXAndRiskWithoutScoringInbound(t *testing.T) {
	wallets := []HolderClusterWallet{{
		Wallet: "WalletA", HolderPercentage: 10,
		FlowObservations: []HolderClusterFlowObservation{
			{SourceWallet: "WalletA", Destination: "CEXWallet", Direction: "outbound", Kind: "external_token_recipient", TransferType: "CEX_OUT", Signature: "sig-out"},
			{SourceWallet: "CEXWallet", Destination: "WalletA", Direction: "inbound", Kind: "inbound_token_sender_context", TransferType: "CEX_IN", RiskFlag: "MIXER", Signature: "sig-in"},
		},
	}}
	flow := summarizeHolderClusterFlow(wallets)
	if flow.CEXOutflowObservationCount != 1 || flow.CEXInflowObservationCount != 1 || flow.RiskFlagObservationCount != 1 {
		t.Fatalf("unexpected entity counters: %#v", flow)
	}
	if flow.TransactionsWithOutflow != 1 || flow.WalletsWithOutflow != 1 {
		t.Fatalf("inbound context polluted outflow counters: %#v", flow)
	}
	if flow.CommonExitGroupCount != 0 || flow.RiskContribution != 0 {
		t.Fatalf("CEX/risk labels must remain non-scoring context: %#v", flow)
	}
}

func TestHolderClusterTransactionIndexesCoverNewestOldestAndLaunch(t *testing.T) {
	newestTime := int64(300)
	launchTime := int64(200)
	oldestTime := int64(100)
	signatures := []SolanaSignatureInfo{
		{Signature: "newest", BlockTime: &newestTime},
		{Signature: "launch", BlockTime: &launchTime},
		{Signature: "oldest", BlockTime: &oldestTime},
	}
	indexes := holderClusterTransactionIndexes(signatures, launchTime)
	if len(indexes) != 3 {
		t.Fatalf("indexes = %v", indexes)
	}
	seen := map[int]bool{}
	for _, index := range indexes {
		seen[index] = true
	}
	for _, expected := range []int{0, 1, 2} {
		if !seen[expected] {
			t.Fatalf("missing index %d in %v", expected, indexes)
		}
	}
}
