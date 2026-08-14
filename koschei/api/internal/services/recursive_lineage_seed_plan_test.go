package services

import (
	"fmt"
	"testing"
	"time"
)

func TestBuildRecursiveLineageSeedPlanRequiresVerifiedFunder(t *testing.T) {
	now := time.Now().UTC()
	funding := ActorFundingOrigin{
		SourceWallet: "funder-wallet", VerificationStatus: "observed",
		Signature: "sig-1", Slot: 10, ObservedAt: now,
	}
	plan := BuildRecursiveLineageSeedPlan("creator-wallet", funding, HolderIntelligence{})
	if len(plan.Seeds) != 1 || plan.Seeds[0].Wallet != "creator-wallet" {
		t.Fatalf("observed funder must not become a seed: %#v", plan.Seeds)
	}

	funding.VerificationStatus = "verified"
	plan = BuildRecursiveLineageSeedPlan("creator-wallet", funding, HolderIntelligence{})
	if len(plan.Seeds) != 2 || plan.Seeds[1].Wallet != "funder-wallet" || plan.Seeds[1].EvidenceStatus != "verified" {
		t.Fatalf("verified funder should become the second seed: %#v", plan.Seeds)
	}
}

func TestBuildRecursiveLineageSeedPlanFiltersAndCapsHolders(t *testing.T) {
	rows := []HolderIntelligenceRow{
		{Rank: 1, OwnerWallet: "unresolved", OwnerResolved: false, RiskBearing: true, ParsedTransactions: 4},
		{Rank: 2, OwnerWallet: "protocol", OwnerResolved: true, RiskBearing: false, ExcludedFromHolderRisk: true, ParsedTransactions: 4},
		{Rank: 3, OwnerWallet: "quiet", OwnerResolved: true, RiskBearing: true},
	}
	for index := 0; index < 24; index++ {
		rows = append(rows, HolderIntelligenceRow{
			Rank:               index + 4,
			OwnerWallet:        fmt.Sprintf("holder-%02d", index),
			OwnerResolved:      true,
			RiskBearing:        true,
			ParsedTransactions: 1,
		})
	}
	plan := BuildRecursiveLineageSeedPlan("creator", ActorFundingOrigin{}, HolderIntelligence{Rows: rows})
	if plan.HolderCandidatesObserved != 24 {
		t.Fatalf("expected 24 eligible holder candidates, got %d", plan.HolderCandidatesObserved)
	}
	if plan.HolderSeedsIncluded != MaxRecursiveLineageHolderSeeds {
		t.Fatalf("expected %d holder seeds, got %d", MaxRecursiveLineageHolderSeeds, plan.HolderSeedsIncluded)
	}
	if plan.Complete {
		t.Fatalf("holder cap must make the plan incomplete")
	}
	if len(plan.Seeds) != 1+MaxRecursiveLineageHolderSeeds {
		t.Fatalf("expected creator plus capped holders, got %d seeds", len(plan.Seeds))
	}
	if plan.Seeds[1].Wallet != "holder-00" || plan.Seeds[len(plan.Seeds)-1].Wallet != "holder-19" {
		t.Fatalf("holder rank ordering/cap is not deterministic: first=%s last=%s", plan.Seeds[1].Wallet, plan.Seeds[len(plan.Seeds)-1].Wallet)
	}
}

func TestBuildRecursiveLineageSeedPlanDeduplicatesRoles(t *testing.T) {
	now := time.Now().UTC()
	wallet := "same-wallet"
	funding := ActorFundingOrigin{
		SourceWallet: wallet, VerificationStatus: "verified",
		Signature: "sig-2", Slot: 11, ObservedAt: now,
	}
	holders := HolderIntelligence{Rows: []HolderIntelligenceRow{{
		Rank: 1, OwnerWallet: wallet, OwnerResolved: true, RiskBearing: true,
		CommonExitObserved: true,
	}}}
	plan := BuildRecursiveLineageSeedPlan(wallet, funding, holders)
	if len(plan.Seeds) != 1 {
		t.Fatalf("duplicate wallet roles must collapse into one seed: %#v", plan.Seeds)
	}
	seed := plan.Seeds[0]
	wantRoles := map[string]bool{"creator_deployer": true, "primary_funder": true, "critical_holder": true}
	for _, role := range seed.Roles {
		delete(wantRoles, role)
	}
	if len(wantRoles) != 0 {
		t.Fatalf("deduplicated seed lost roles: %#v", seed.Roles)
	}
	if seed.EvidenceStatus != "verified" {
		t.Fatalf("strongest evidence status should win, got %q", seed.EvidenceStatus)
	}
	if seed.HolderRank != 1 {
		t.Fatalf("holder rank should be preserved on merged seed, got %d", seed.HolderRank)
	}
}
