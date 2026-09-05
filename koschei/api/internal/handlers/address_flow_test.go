package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestSelectAddressFlowEntriesSpansHistoryAndSkipsFailed(t *testing.T) {
	entries := []services.AddressHistoryEntry{
		{Signature: "sig5", Status: "success"},
		{Signature: "sig4", Status: "failed"},
		{Signature: "sig3", Status: "success"},
		{Signature: "sig2", Status: "success"},
		{Signature: "sig1", Status: "success"},
	}
	selected := selectAddressFlowEntries(entries, 2)
	if len(selected) != 2 {
		t.Fatalf("selected=%d", len(selected))
	}
	if selected[0].Signature != "sig5" || selected[1].Signature != "sig1" {
		t.Fatalf("selected=%#v", selected)
	}
}

func TestAddressFlowTransferFromEvidenceAndCounterpartyAggregation(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	rows := []services.ActorDefenseEvidenceRecord{
		{
			Relation: "direct_sol_transfer_in", CounterpartID: "SourceWallet", Signature: "sig-in",
			Slot: 10, ObservedAt: now, AmountNative: 2.5, VerificationStatus: "verified", Source: "solana_jsonparsed_instruction",
		},
		{
			Relation: "direct_sol_transfer_out", CounterpartID: "DestWallet", Signature: "sig-out",
			Slot: 11, ObservedAt: now.Add(time.Minute), AmountNative: 1.25, VerificationStatus: "verified", Source: "solana_jsonparsed_instruction",
		},
		{
			Relation: "direct_token_transfer_out", CounterpartID: "DestWallet", Signature: "sig-token",
			Slot: 12, ObservedAt: now.Add(2 * time.Minute), TokenMint: "MintABC", TokenAmount: 4,
			VerificationStatus: "verified", Source: "solana_jsonparsed_instruction",
		},
	}
	state := map[string]*addressFlowCounterpartyBuilder{}
	for _, row := range rows {
		transfer, ok := addressFlowTransferFromEvidence(row)
		if !ok {
			t.Fatalf("evidence did not become transfer: %#v", row)
		}
		applyAddressFlowCounterparty(state, transfer)
	}
	counterparties := buildAddressFlowCounterparties(state)
	if len(counterparties) != 2 {
		t.Fatalf("counterparties=%#v", counterparties)
	}
	var destination addressFlowCounterparty
	for _, item := range counterparties {
		if item.Address == "DestWallet" {
			destination = item
		}
	}
	if destination.OutboundTransfers != 2 || destination.SOLOut != 1.25 || destination.TokenTransfersOut != 1 {
		t.Fatalf("destination=%#v", destination)
	}
	if len(destination.TokenMints) != 1 || destination.TokenMints[0] != "MintABC" {
		t.Fatalf("token_mints=%#v", destination.TokenMints)
	}
}

func TestAddressFlowTransferRejectsNonFlowEvidence(t *testing.T) {
	_, ok := addressFlowTransferFromEvidence(services.ActorDefenseEvidenceRecord{
		Relation: "liquidity_remove_activity", CounterpartID: "PoolABC",
	})
	if ok {
		t.Fatal("non-transfer evidence must not be projected as direct fund flow")
	}
}
