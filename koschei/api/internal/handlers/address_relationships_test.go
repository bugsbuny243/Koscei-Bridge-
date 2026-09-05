package handlers

import (
	"testing"
	"time"
)

func TestBuildAddressRelationshipsAggregatesBidirectionalEvidence(t *testing.T) {
	first := time.Date(2026, 9, 1, 10, 0, 0, 0, time.UTC)
	last := first.Add(48 * time.Hour)
	flow := addressFlowReport{
		FlowComplete: true,
		Transfers: []addressFlowTransfer{
			{Direction: "inbound", AssetType: "SOL", Counterparty: "WalletB", Signature: "sig-in", ObservedAt: first},
			{Direction: "outbound", AssetType: "SPL_TOKEN", Counterparty: "WalletB", Signature: "sig-out", ObservedAt: last, TokenMint: "MintABC"},
		},
	}
	attribution := addressAttributionReport{Entities: []addressAttributionEntity{{
		Address: "WalletB", Entity: "Known Entity", Category: "Centralized Exchange", Source: "helius_identity",
	}}}

	report := buildAddressRelationships("WalletA", flow, attribution)
	if report.RelationshipCount != 1 || report.Status != "direct_relationships_available" {
		t.Fatalf("report=%#v", report)
	}
	row := report.Relationships[0]
	if row.Relation != "bidirectional_direct_flow" || row.InboundTransfers != 1 || row.OutboundTransfers != 1 {
		t.Fatalf("row=%#v", row)
	}
	if !row.FirstObservedAt.Equal(first) || !row.LastObservedAt.Equal(last) {
		t.Fatalf("first=%s last=%s", row.FirstObservedAt, row.LastObservedAt)
	}
	if row.AttributedEntity != "Known Entity" || row.AttributionSource != "helius_identity" {
		t.Fatalf("row=%#v", row)
	}
	if row.SameActorClaimed || row.IdentityClaimed {
		t.Fatalf("direct flow must not become identity claim: %#v", row)
	}
}

func TestBuildAddressRelationshipsDeduplicatesAndBoundsEvidence(t *testing.T) {
	flow := addressFlowReport{FlowComplete: true, Transfers: []addressFlowTransfer{}}
	for i := 0; i < 20; i++ {
		flow.Transfers = append(flow.Transfers, addressFlowTransfer{
			Direction: "outbound", AssetType: "SPL_TOKEN", Counterparty: "WalletB",
			Signature: "sig-duplicate", TokenMint: "MintSame", ObservedAt: time.Date(2026, 9, 1, 0, i, 0, 0, time.UTC),
		})
	}
	report := buildAddressRelationships("WalletA", flow, addressAttributionReport{})
	row := report.Relationships[0]
	if len(row.EvidenceSignatures) != 1 || row.EvidenceSignatures[0] != "sig-duplicate" {
		t.Fatalf("signatures=%#v", row.EvidenceSignatures)
	}
	if len(row.TokenMints) != 1 || row.TokenMints[0] != "MintSame" {
		t.Fatalf("mints=%#v", row.TokenMints)
	}
}

func TestBuildAddressRelationshipsMarksIncompleteCoverage(t *testing.T) {
	report := buildAddressRelationships("WalletA", addressFlowReport{
		FlowComplete: false,
		Transfers: []addressFlowTransfer{{Direction: "inbound", AssetType: "SOL", Counterparty: "WalletB", Signature: "sig1"}},
	}, addressAttributionReport{})
	if len(report.Limitations) == 0 {
		t.Fatal("bounded flow must propagate a relationship coverage limitation")
	}
	if report.Policy["same_actor_claim_requires_separate_evidence"] != true || report.Policy["real_person_identity_claim"] != false {
		t.Fatalf("policy=%#v", report.Policy)
	}
}
