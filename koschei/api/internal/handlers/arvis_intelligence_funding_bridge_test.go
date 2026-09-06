package handlers

import (
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestApplyArvisFundingRelationshipProjectsVerifiedFundingEvidence(t *testing.T) {
	const mint = "62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump"
	const creator = "11111111111111111111111111111111"
	const source = "So11111111111111111111111111111111111111112"
	now := time.Date(2026, 9, 6, 7, 45, 0, 0, time.UTC)
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{
		services.ClassifyIntelligenceSubject(mint, "solana-mainnet"),
	}, now)

	origin := services.ActorFundingOrigin{
		Wallet:             creator,
		Status:             "initial_funding_observed",
		HistoryComplete:    true,
		SourceWallet:       source,
		DestinationWallet:  creator,
		AmountSOL:          1.25,
		Signature:          "funding-sig",
		Slot:               987,
		ObservedAt:         now,
		Program:            "system",
		InstructionType:    "transfer",
		VerificationStatus: "verified",
		TrailStatus:        "source_wallet_observed",
		IdentityScope:      "onchain_wallet_only",
		ResultState:        services.ActorFundingResultVerified,
	}

	applyArvisFundingRelationship(&investigation, origin, "solana-mainnet")

	if len(investigation.Relationships) != 1 {
		t.Fatalf("expected one funding relationship, got %#v", investigation.Relationships)
	}
	if investigation.Relationships[0].Status != services.IntelligenceEvidenceVerified {
		t.Fatalf("expected verified relationship, got %#v", investigation.Relationships[0])
	}
	if investigation.Relationships[0].Relation != "initial_funding_in" {
		t.Fatalf("unexpected relation: %#v", investigation.Relationships[0])
	}
	if len(investigation.Evidence) != 1 || investigation.Evidence[0].Provenance != "existing_arvis_funding_origin_evidence" {
		t.Fatalf("expected canonical ARVIS funding evidence projection, got %#v", investigation.Evidence)
	}
	if len(investigation.Entities) != 1 || investigation.Entities[0].Attribution != "onchain_role_only" {
		t.Fatalf("funding source must remain on-chain role only: %#v", investigation.Entities)
	}
}

func TestApplyArvisFundingRelationshipRejectsBoundedFundingResult(t *testing.T) {
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{
		services.ClassifyIntelligenceSubject("62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump", "solana-mainnet"),
	}, time.Now().UTC())
	origin := services.ActorFundingOrigin{
		Wallet:             "11111111111111111111111111111111",
		SourceWallet:       "So11111111111111111111111111111111111111112",
		DestinationWallet:  "11111111111111111111111111111111",
		Signature:          "candidate-only",
		Slot:               55,
		VerificationStatus: "verified",
		ResultState:        services.ActorFundingResultBounded,
	}

	applyArvisFundingRelationship(&investigation, origin, "solana-mainnet")
	if len(investigation.Evidence) != 0 || len(investigation.Relationships) != 0 {
		t.Fatalf("bounded funding search must not become graph evidence: evidence=%#v relationships=%#v", investigation.Evidence, investigation.Relationships)
	}
}

func TestApplyArvisFundingRelationshipKeepsObservedEvidenceObserved(t *testing.T) {
	const creator = "11111111111111111111111111111111"
	investigation := services.BuildIntelligenceInvestigation([]services.IntelligenceSubject{
		services.ClassifyIntelligenceSubject("62tJyrfNfYJ2qZncdbwFYmeJmSFn66BhGfgj491ppump", "solana-mainnet"),
	}, time.Now().UTC())
	origin := services.ActorFundingOrigin{
		Wallet:             creator,
		SourceWallet:       "So11111111111111111111111111111111111111112",
		DestinationWallet:  creator,
		Signature:          "observed-funding",
		Slot:               77,
		ObservedAt:         time.Now().UTC(),
		VerificationStatus: "observed",
		TrailStatus:        "source_wallet_observed",
		ResultState:        services.ActorFundingResultVerified,
	}

	applyArvisFundingRelationship(&investigation, origin, "solana-mainnet")
	if len(investigation.Relationships) != 1 || investigation.Relationships[0].Status != services.IntelligenceEvidenceObserved {
		t.Fatalf("observed ARVIS funding evidence must remain observed: %#v", investigation.Relationships)
	}
}
