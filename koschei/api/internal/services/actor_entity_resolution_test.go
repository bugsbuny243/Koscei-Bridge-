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
				ObservedAt: now, Source: "solana_jsonparsed_instruction", EvidenceKey: "funding:1",
			},
			{
				ActorWallet: "Actor111", CounterpartKind: "token", CounterpartID: "Mint111",
				Relation: "created_token", VerificationStatus: "observed", Signature: "Create111", Slot: 100,
				ObservedAt: now.Add(time.Minute), Source: "solana_jsonparsed_instruction", EvidenceKey: "creation:1",
			},
		},
	}

	resolution := BuildActorEntityResolution(dossier)
	if !resolution.Available || resolution.RootEntity != "Actor111" {
		t.Fatalf("unexpected resolution status: %#v", resolution)
	}
	if resolution.EntityCount != 3 || resolution.RelationshipCount != 2 {
		t.Fatalf("unexpected entity/relationship counts: %#v", resolution)
	}
	if resolution.VerifiedRelations != 1 || resolution.ObservedRelations != 1 {
		t.Fatalf("verification counts lost: %#v", resolution)
	}
	if resolution.Policy["no_common_ownership_inference"] != true || resolution.Policy["identity_or_wrongdoing_claim"] != false {
		t.Fatalf("entity safeguards missing: %#v", resolution.Policy)
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
	}
	if !foundFunding {
		t.Fatal("funding relationship missing")
	}
}

func TestBuildActorEntityResolutionDoesNotCreateRelationshipsFromInventory(t *testing.T) {
	resolution := BuildActorEntityResolution(ActorDefenseDossier{
		Wallet: "Actor111",
		Tokens: []ActorDefenseTokenObservation{{Mint: "Mint111"}},
	})
	if resolution.Available || resolution.RelationshipCount != 0 {
		t.Fatalf("inventory fabricated relationship: %#v", resolution)
	}
	if resolution.EntityCount != 2 {
		t.Fatalf("expected known evidence subjects only: %#v", resolution.Entities)
	}
}
