package services

import (
	"testing"
	"time"
)

func TestBuildActorEntityResolutionPromotesEvidenceSubjectsWithoutIdentityInference(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	dossier := ActorDefenseDossier{
		Wallet: "Actor111",
		Tokens: []ActorDefenseTokenObservation{{
			Mint: "Mint111", Roles: []string{"creator_deployer"}, CreatorSignature: "Create111",
		}},
		Evidence: []ActorDefenseEvidenceRecord{
			{
				ActorWallet: "Actor111", CounterpartKind: "wallet", CounterpartID: "Funder111",
				Relation: "funded_by", VerificationStatus: "verified", Signature: "Fund111", Slot: 90,
				ObservedAt: now, Source: "solana_jsonparsed_instruction", EvidenceKey: "funding:1", AmountNative: 1.25,
			},
			{
				ActorWallet: "Actor111", CounterpartKind: "token", CounterpartID: "Mint111",
				Relation: "created_token", VerificationStatus: "observed", Signature: "Create111", Slot: 100,
				ObservedAt: now.Add(time.Minute), Source: "solana_jsonparsed_instruction", EvidenceKey: "creation:1", TokenMint: "Mint111",
			},
		},
	}

	resolution := BuildActorEntityResolution(dossier)
	if !resolution.Available || resolution.RootEntity != "Actor111" {
		t.Fatalf("unexpected resolution status: %#v", resolution)
	}
	if resolution.EntityCount != 3 || resolution.RelationshipCount != 2 || resolution.TransactionCount != 2 {
		t.Fatalf("unexpected entity/relationship/transaction counts: %#v", resolution)
	}
	if resolution.VerifiedRelations != 1 || resolution.ObservedRelations != 1 {
		t.Fatalf("verification counts lost: %#v", resolution)
	}
	if resolution.Policy["no_common_ownership_inference"] != true || resolution.Policy["identity_or_wrongdoing_claim"] != false {
		t.Fatalf("entity safeguards missing: %#v", resolution.Policy)
	}
	if resolution.Policy["transaction_projection_requires_signature"] != true || resolution.Policy["identifiers_are_case_sensitive"] != true {
		t.Fatalf("transaction or identifier safeguards missing: %#v", resolution.Policy)
	}
	foundFunding := false
	for _, relation := range resolution.Relationships {
		if relation.Relation != "funded_by" {
			continue
		}
		foundFunding = true
		if relation.SourceEntity != "Funder111" || relation.TargetEntity != "Actor111" || relation.EvidenceKey != "funding:1" {
			t.Fatalf("funding relationship provenance lost: %#v", relation)
		}
		if relation.ObservedAt != now || relation.NativeAmount != 1.25 {
			t.Fatalf("funding relationship transaction evidence lost: %#v", relation)
		}
	}
	if !foundFunding {
		t.Fatal("funding relationship missing")
	}
	foundTransaction := false
	for _, transaction := range resolution.Transactions {
		if transaction.Signature != "Fund111" {
			continue
		}
		foundTransaction = true
		if transaction.Slot != 90 || transaction.VerificationStatus != "verified" || transaction.ObservedAt != now {
			t.Fatalf("funding transaction provenance lost: %#v", transaction)
		}
		if len(transaction.EntityIDs) != 2 || transaction.EntityIDs[0] != "Actor111" || transaction.EntityIDs[1] != "Funder111" {
			t.Fatalf("funding transaction entity projection is wrong: %#v", transaction.EntityIDs)
		}
		if len(transaction.EvidenceKeys) != 1 || transaction.EvidenceKeys[0] != "funding:1" {
			t.Fatalf("funding transaction evidence key missing: %#v", transaction.EvidenceKeys)
		}
	}
	if !foundTransaction {
		t.Fatal("funding transaction projection missing")
	}
}

func TestBuildActorEntityResolutionDoesNotCreateRelationshipsFromInventory(t *testing.T) {
	resolution := BuildActorEntityResolution(ActorDefenseDossier{
		Wallet: "Actor111",
		Tokens: []ActorDefenseTokenObservation{{Mint: "Mint111"}},
	})
	if resolution.Available || resolution.RelationshipCount != 0 || resolution.TransactionCount != 0 {
		t.Fatalf("inventory fabricated relationship or transaction: %#v", resolution)
	}
	if resolution.EntityCount != 2 {
		t.Fatalf("expected known evidence subjects only: %#v", resolution.Entities)
	}
}

func TestBuildActorEntityResolutionPreservesCaseSensitiveSubjects(t *testing.T) {
	now := time.Unix(1700000200, 0).UTC()
	resolution := BuildActorEntityResolution(ActorDefenseDossier{
		Wallet: "Actor111",
		Evidence: []ActorDefenseEvidenceRecord{
			{
				ActorWallet: "Actor111", CounterpartKind: "wallet", CounterpartID: "CaseAa",
				Relation: "observed_counterparty", VerificationStatus: "observed", Signature: "SigCase1", Slot: 110,
				ObservedAt: now, Source: "solana_jsonparsed_instruction", EvidenceKey: "case:1",
			},
			{
				ActorWallet: "Actor111", CounterpartKind: "wallet", CounterpartID: "CaseaA",
				Relation: "observed_counterparty", VerificationStatus: "observed", Signature: "SigCase2", Slot: 111,
				ObservedAt: now.Add(time.Second), Source: "solana_jsonparsed_instruction", EvidenceKey: "case:2",
			},
		},
	})
	if resolution.EntityCount != 3 || resolution.RelationshipCount != 2 || resolution.TransactionCount != 2 {
		t.Fatalf("case-sensitive subjects were collapsed: %#v", resolution)
	}
}

func TestBuildActorEntityResolutionDoesNotPromoteUnsignedEvidenceToTransaction(t *testing.T) {
	resolution := BuildActorEntityResolution(ActorDefenseDossier{
		Wallet: "Actor111",
		Evidence: []ActorDefenseEvidenceRecord{{
			ActorWallet: "Actor111", CounterpartKind: "service", CounterpartID: "ObservedService",
			Relation: "external_account_attribution", VerificationStatus: "observed",
			Source: "solscan_pro_api_v2", EvidenceKey: "attribution:1",
		}},
	})
	if resolution.RelationshipCount != 1 || resolution.TransactionCount != 0 {
		t.Fatalf("unsigned evidence was fabricated into a transaction: %#v", resolution)
	}
	if resolution.Policy["unsigned_relationship_not_promoted_to_transaction"] != true {
		t.Fatalf("unsigned-relationship transaction safeguard missing: %#v", resolution.Policy)
	}
}
