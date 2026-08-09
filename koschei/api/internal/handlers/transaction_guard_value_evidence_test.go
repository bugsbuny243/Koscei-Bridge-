package handlers

import (
	"strings"
	"testing"
)

func intValue(value int) *int { return &value }

func completeTransactionValueFixture() (transactionGuardDecodedTransaction, transactionGuardCPIFlowAnalysis) {
	decoded := transactionGuardDecodedTransaction{
		Available: true,
		Complete:  true,
		SOLTransfers: []transactionGuardDecodedSOLTransfer{
			{Kind: "transfer", Source: "WalletA", Recipient: "RecipientA", Lamports: "100"},
			{Kind: "create_account", Source: "OtherWallet", Recipient: "CreatedA", Lamports: "25"},
		},
		TokenOperations: []transactionGuardDecodedTokenOperation{
			{Kind: "transfer", ProgramID: guardV3SPLTokenProgramID, Source: "WalletTokenA", Destination: "DestTokenA", AmountRaw: "10"},
			{Kind: "burn_checked", ProgramID: guardV3SPLTokenProgramID, Account: "WalletTokenA", Mint: "MintA", Authority: "WalletA", AmountRaw: "5", Decimals: intValue(6)},
		},
		AutomaticBalance: transactionGuardAutomaticBalanceAnalysis{
			Requested:                 true,
			Available:                 true,
			Complete:                  true,
			Status:                    "verified_rpc_simulation_balance_changes",
			Wallet:                    "WalletA",
			WalletSOLDeltaLamports:    "-180",
			WalletSOLSpentLamports:    "180",
			WalletSOLReceivedLamports: "0",
			Accounts: []transactionGuardAutomaticBalanceDelta{
				{Address: "WalletTokenA", TokenAccount: true, Mint: "MintA", PreTokenOwner: "WalletA", PostTokenOwner: "WalletA", EvidenceStatus: "verified_rpc_simulation"},
				{Address: "DestTokenA", TokenAccount: true, Mint: "MintA", PreTokenOwner: "RecipientWallet", PostTokenOwner: "RecipientWallet", EvidenceStatus: "verified_rpc_simulation"},
			},
		},
	}
	cpi := transactionGuardCPIFlowAnalysis{
		Requested: true,
		Required:  true,
		Available: true,
		Complete:  true,
		Status:    "complete",
		AssetMovements: []transactionGuardCPIAssetMovement{
			{AssetType: "SOL", Kind: "transfer", Source: "WalletA", Destination: "RecipientA", AmountRaw: "100", InnerOnly: false, WalletOrigin: true},
			{AssetType: "SOL", Kind: "transfer", Source: "WalletA", Destination: "InnerRecipient", AmountRaw: "50", InnerOnly: true, WalletOrigin: true},
			{AssetType: "token", Kind: "transfer", Source: "WalletTokenA", Destination: "DestTokenA", Mint: "MintA", AmountRaw: "10", InnerOnly: false, WalletOrigin: true},
			{AssetType: "token", Kind: "transfer_checked", Source: "WalletTokenA", Destination: "InnerTokenDest", Mint: "MintA", AmountRaw: "7", Decimals: intValue(6), InnerOnly: true, WalletOrigin: true},
		},
	}
	return decoded, cpi
}

func TestTransactionValueEvidenceSeparatesExplicitAndObservedSOL(t *testing.T) {
	decoded, cpi := completeTransactionValueFixture()
	got := buildTransactionGuardValueEvidence("fixture-transaction", "WalletA", decoded, cpi)
	if !got.Complete || got.Status != "complete" {
		t.Fatalf("evidence=%#v", got)
	}
	if got.ExplicitSOLLamports != "175" {
		t.Fatalf("explicit SOL=%s want=175", got.ExplicitSOLLamports)
	}
	if got.WalletExplicitSOLOutflowLamports != "150" {
		t.Fatalf("wallet explicit SOL=%s want=150", got.WalletExplicitSOLOutflowLamports)
	}
	if got.WalletObservedSOLDeltaLamports != "-180" || got.WalletObservedSOLSpentLamports != "180" {
		t.Fatalf("observed wallet delta/spend=%s/%s", got.WalletObservedSOLDeltaLamports, got.WalletObservedSOLSpentLamports)
	}
	if len(got.SOLMovements) != 3 {
		t.Fatalf("duplicate outer/inner SOL was double-counted: %#v", got.SOLMovements)
	}
	if got.FeeStatus != "unavailable_no_verified_fee_evidence" || got.PriceStatus != "not_requested_v1" || got.PolicyUseStatus != "evidence_only_not_enforced" {
		t.Fatalf("safety statuses=%#v", got)
	}
}

func TestTransactionValueEvidenceAggregatesTokenRawAmountsByMintWithoutDoubleCountingCPI(t *testing.T) {
	decoded, cpi := completeTransactionValueFixture()
	got := buildTransactionGuardValueEvidence("fixture-transaction", "WalletA", decoded, cpi)
	if got.UnscopedTokenMovementCount != 0 || len(got.TokenAggregates) != 1 {
		t.Fatalf("token evidence=%#v", got)
	}
	aggregate := got.TokenAggregates[0]
	if aggregate.Mint != "MintA" || aggregate.TransferRaw != "17" || aggregate.WalletOriginTransferRaw != "17" {
		t.Fatalf("transfer aggregate=%#v", aggregate)
	}
	if aggregate.BurnRaw != "5" || aggregate.WalletOriginBurnRaw != "5" || aggregate.MovementCount != 3 || aggregate.WalletOriginMovementCount != 3 {
		t.Fatalf("burn/movement aggregate=%#v", aggregate)
	}
	if aggregate.Decimals == nil || *aggregate.Decimals != 6 || !aggregate.DecimalsConsistent {
		t.Fatalf("decimals aggregate=%#v", aggregate)
	}
	if len(got.TokenMovements) != 3 {
		t.Fatalf("duplicate outer/inner token transfer was double-counted: %#v", got.TokenMovements)
	}
}

func TestTransactionValueEvidenceIsPartialWhenCPICoverageIncomplete(t *testing.T) {
	decoded, cpi := completeTransactionValueFixture()
	cpi.Complete = false
	cpi.UnresolvedInstructionCount = 2
	got := buildTransactionGuardValueEvidence("fixture-transaction", "WalletA", decoded, cpi)
	if got.Complete || got.Status != "partial" || got.UnresolvedCPIInstructionCount != 2 {
		t.Fatalf("evidence=%#v", got)
	}
	joined := strings.Join(got.Limitations, " ")
	if !strings.Contains(joined, "CPI asset-flow decoding is incomplete") {
		t.Fatalf("limitations=%v", got.Limitations)
	}
}

func TestTransactionValueEvidenceUnscopedTokenMovementIsNotMintAggregate(t *testing.T) {
	decoded := transactionGuardDecodedTransaction{
		Available: true,
		Complete:  true,
		TokenOperations: []transactionGuardDecodedTokenOperation{
			{Kind: "transfer", ProgramID: guardV3SPLTokenProgramID, Source: "UnknownSource", Destination: "UnknownDestination", AmountRaw: "9", Authority: "WalletA"},
		},
		AutomaticBalance: transactionGuardAutomaticBalanceAnalysis{Requested: false},
	}
	got := buildTransactionGuardValueEvidence("fixture-transaction", "WalletA", decoded, transactionGuardCPIFlowAnalysis{Requested: false})
	if got.UnscopedTokenMovementCount != 1 || len(got.TokenAggregates) != 0 || len(got.TokenMovements) != 1 {
		t.Fatalf("evidence=%#v", got)
	}
	if got.TokenMovements[0].Mint != "" || !got.TokenMovements[0].WalletOrigin {
		t.Fatalf("movement=%#v", got.TokenMovements[0])
	}
}

func TestTransactionValueEvidenceHashIsDeterministicAndStateSensitive(t *testing.T) {
	decoded, cpi := completeTransactionValueFixture()
	first := buildTransactionGuardValueEvidence("fixture-transaction", "WalletA", decoded, cpi)
	second := buildTransactionGuardValueEvidence("fixture-transaction", "WalletA", decoded, cpi)
	if first.EvidenceHashSHA256 == "" || first.EvidenceHashSHA256 != second.EvidenceHashSHA256 {
		t.Fatalf("hash mismatch %q != %q", first.EvidenceHashSHA256, second.EvidenceHashSHA256)
	}
	decoded.SOLTransfers[0].Lamports = "101"
	changed := buildTransactionGuardValueEvidence("fixture-transaction", "WalletA", decoded, cpi)
	if changed.EvidenceHashSHA256 == first.EvidenceHashSHA256 {
		t.Fatal("value evidence hash did not change after explicit SOL movement changed")
	}
}
