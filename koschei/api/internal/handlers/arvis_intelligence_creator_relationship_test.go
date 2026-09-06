package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestApplyArvisCreatorRelationshipRequiresCanonicalEvidence(t *testing.T) {
	now := time.Date(2026, 9, 6, 7, 45, 0, 0, time.UTC)
	mint := "62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump"
	creator := "9xQeWvG816bUx9EPm9JcRj5kq5kH2VQb4Y2M6Yq7YpQp"
	investigation := buildArvisIntelligenceBridge(mint, "solana-mainnet", nil, now)

	applyArvisCreatorRelationship(&investigation, actorCreatorRelationRun{
		Target: services.ActorDistributionTarget{CreatorWallet: creator, Mint: mint},
		Evidence: services.ActorDefenseEvidenceRecord{
			EvidenceKey: "",
		},
	}, "solana-mainnet")

	if len(investigation.Relationships) != 0 || len(investigation.Entities) != 0 {
		t.Fatalf("missing canonical evidence key must not create entity/relationship: %#v %#v", investigation.Entities, investigation.Relationships)
	}
}

func TestApplyArvisCreatorRelationshipVerifiedOnlyWithSignatureAndSlot(t *testing.T) {
	now := time.Date(2026, 9, 6, 7, 45, 0, 0, time.UTC)
	mint := "62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump"
	creator := "9xQeWvG816bUx9EPm9JcRj5kq5kH2VQb4Y2M6Yq7YpQp"
	investigation := buildArvisIntelligenceBridge(mint, "solana-mainnet", nil, now)

	applyArvisCreatorRelationship(&investigation, actorCreatorRelationRun{
		Target: services.ActorDistributionTarget{CreatorWallet: creator, Mint: mint},
		Evidence: services.ActorDefenseEvidenceRecord{
			EvidenceKey:        "canonical_creator_relation:" + mint,
			VerificationStatus: "verified",
			Source:             "pumpportal",
			Signature:          "launch-signature",
			Slot:               123456,
			ObservedAt:         now,
		},
	}, "solana-mainnet")

	if len(investigation.Subjects) != 2 {
		t.Fatalf("expected mint and creator subjects, got %#v", investigation.Subjects)
	}
	if len(investigation.Evidence) != 1 || investigation.Evidence[0].Status != services.IntelligenceEvidenceVerified {
		t.Fatalf("expected verified canonical creator evidence, got %#v", investigation.Evidence)
	}
	if len(investigation.Entities) != 1 || investigation.Entities[0].Attribution != "onchain_role_only" {
		t.Fatalf("expected evidence-backed onchain creator entity, got %#v", investigation.Entities)
	}
	if len(investigation.Relationships) != 1 || investigation.Relationships[0].Status != services.IntelligenceEvidenceVerified {
		t.Fatalf("expected verified creator->mint relationship, got %#v", investigation.Relationships)
	}
}

func TestApplyArvisCreatorRelationshipVerifiedFlagWithoutSlotStaysObserved(t *testing.T) {
	now := time.Date(2026, 9, 6, 7, 45, 0, 0, time.UTC)
	mint := "62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump"
	creator := "9xQeWvG816bUx9EPm9JcRj5kq5kH2VQb4Y2M6Yq7YpQp"
	investigation := buildArvisIntelligenceBridge(mint, "solana-mainnet", nil, now)

	applyArvisCreatorRelationship(&investigation, actorCreatorRelationRun{
		Target: services.ActorDistributionTarget{CreatorWallet: creator, Mint: mint},
		Evidence: services.ActorDefenseEvidenceRecord{
			EvidenceKey:        "canonical_creator_relation:" + mint,
			VerificationStatus: "verified",
			Source:             "canonical_token_radar",
			Signature:          "launch-signature",
			Slot:               0,
			ObservedAt:         now,
		},
	}, "solana-mainnet")

	if len(investigation.Relationships) != 1 || investigation.Relationships[0].Status != services.IntelligenceEvidenceObserved {
		t.Fatalf("verified flag without slot must remain observed: %#v", investigation.Relationships)
	}
	if investigation.Evidence[0].Status != services.IntelligenceEvidenceObserved {
		t.Fatalf("evidence must remain observed without signature+slot completeness: %#v", investigation.Evidence)
	}
}
