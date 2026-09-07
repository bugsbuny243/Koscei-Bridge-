package services

import (
	"testing"
	"time"
)

func TestBuildActorEvidenceGraphPreservesEvidenceDirectionAndStatus(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	dossier := ActorDefenseDossier{
		Wallet: "Creator111",
		Tokens: []ActorDefenseTokenObservation{
			{Mint: "Mint111", Roles: []string{"creator_deployer"}, CreatorSignature: "CreateSig111", FirstObservedAt: now, LastObservedAt: now},
		},
		RelatedActors: []ActorDefenseRelatedActor{},
		Evidence: []ActorDefenseEvidenceRecord{
			{
				ActorWallet: "Creator111", CounterpartKind: "token", CounterpartID: "Mint111",
				Relation: "created_token", VerificationStatus: "verified", Signature: "CreateSig111", Slot: 100,
				ObservedAt: now, TokenMint: "Mint111", Source: "solana_jsonparsed_instruction", Metadata: map[string]any{},
			},
			{
				ActorWallet: "Creator111", CounterpartKind: "wallet", CounterpartID: "Funder111",
				Relation: "funded_by", VerificationStatus: "verified", Signature: "FundSig111", Slot: 90,
				ObservedAt: now.Add(-time.Minute), AmountNative: 1.25, Source: "solana_jsonparsed_instruction", Metadata: map[string]any{},
			},
			{
				ActorWallet: "Creator111", CounterpartKind: "service", CounterpartID: "Creator111",
				Relation: "external_account_attribution", VerificationStatus: "observed", ObservedAt: now,
				Source: "solscan_pro_api_v2", Metadata: map[string]any{"label": "Example Hot Wallet"},
			},
		},
	}

	graph := BuildActorEvidenceGraph(dossier)
	if !graph.Available || graph.EdgeCount != 3 || graph.VerifiedEdges != 2 || graph.ObservedEdges != 1 {
		t.Fatalf("unexpected graph coverage: %#v", graph)
	}
	foundFunding := false
	for _, edge := range graph.Edges {
		if edge.Relation == "funded_by" {
			foundFunding = true
			if edge.Source != "Funder111" || edge.Target != "Creator111" {
				t.Fatalf("funding edge direction is wrong: %#v", edge)
			}
			if edge.NativeAmount != 1.25 {
				t.Fatalf("funding amount was lost: %#v", edge)
			}
		}
	}
	if !foundFunding {
		t.Fatal("funding edge missing")
	}
	if graph.Policy["identity_or_wrongdoing_claim"] != false {
		t.Fatalf("graph policy lost identity safeguard: %#v", graph.Policy)
	}
}

func TestBuildActorEvidenceGraphDoesNotCreateEdgesWithoutEvidence(t *testing.T) {
	graph := BuildActorEvidenceGraph(ActorDefenseDossier{Wallet: "Creator111", Tokens: []ActorDefenseTokenObservation{{Mint: "Mint111"}}})
	if graph.Available || graph.EdgeCount != 0 {
		t.Fatalf("token inventory created an evidence edge: %#v", graph)
	}
	if graph.NodeCount != 2 {
		t.Fatalf("expected actor and known token nodes only, got %#v", graph.Nodes)
	}
}

func TestBuildActorEvidenceGraphPreservesCaseSensitiveIdentifiers(t *testing.T) {
	now := time.Unix(1700000100, 0).UTC()
	graph := BuildActorEvidenceGraph(ActorDefenseDossier{
		Wallet: "Actor111",
		Evidence: []ActorDefenseEvidenceRecord{
			{
				ActorWallet: "Actor111", CounterpartKind: "wallet", CounterpartID: "CaseAa",
				Relation: "observed_counterparty", VerificationStatus: "observed", Signature: "Sig111", Slot: 101,
				ObservedAt: now, Source: "solana_jsonparsed_instruction", EvidenceKey: "case:1",
			},
			{
				ActorWallet: "Actor111", CounterpartKind: "wallet", CounterpartID: "CaseaA",
				Relation: "observed_counterparty", VerificationStatus: "observed", Signature: "Sig111", Slot: 101,
				ObservedAt: now, Source: "solana_jsonparsed_instruction", EvidenceKey: "case:2",
			},
		},
	})
	if graph.NodeCount != 3 || graph.EdgeCount != 2 {
		t.Fatalf("case-sensitive identifiers were collapsed: %#v", graph)
	}
	if graph.Policy["identifiers_are_case_sensitive"] != true {
		t.Fatalf("case-sensitive identifier policy missing: %#v", graph.Policy)
	}
}
