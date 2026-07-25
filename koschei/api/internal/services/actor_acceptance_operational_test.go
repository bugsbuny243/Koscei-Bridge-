package services

import (
	"strings"
	"testing"
	"time"
)

func TestOperationalAcceptanceRejectsFalseMatchWithoutCompletedHolderSource(t *testing.T) {
	observed := time.Date(2026, 7, 25, 18, 0, 0, 0, time.UTC)
	row := actorAcceptanceTestEvidence("creator", "recipient", "initial_token_recipient", "sig-recipient", 100, observed, "spl-token", 10, "mint-a")
	row.Metadata["matches_top_holder"] = false

	result := EvaluateOperationalActorAcceptance(ActorAcceptanceInput{
		Wallet: "creator", Network: "solana-mainnet", TargetKind: "wallet",
		Dossier: ActorDefenseDossier{Wallet: "creator", Network: "solana-mainnet", Evidence: []ActorDefenseEvidenceRecord{row}},
		FundingOrigin: ActorFundingOrigin{Status: "not_investigated", TrailStatus: "not_investigated"},
	})

	item := result.Items[5]
	if item.ID != "AC-06" || item.Status != ActorAcceptanceFail || item.EvidenceState != "not_verified" {
		t.Fatalf("holder comparison without a completed source must fail closed: %+v", item)
	}
	if !strings.Contains(item.Limitations[0], "missing") {
		t.Fatalf("missing holder-source status must remain visible: %+v", item.Limitations)
	}
}

func TestOperationalAcceptanceAcceptsCompletedZeroTopHolderMatch(t *testing.T) {
	observed := time.Date(2026, 7, 25, 18, 0, 0, 0, time.UTC)
	row := actorAcceptanceTestEvidence("creator", "recipient", "initial_token_recipient", "sig-recipient", 100, observed, "spl-token", 10, "mint-a")
	row.Metadata["matches_top_holder"] = false
	row.Metadata["top_holder_status"] = "verified_role_resolution"

	result := EvaluateOperationalActorAcceptance(ActorAcceptanceInput{
		Wallet: "creator", Network: "solana-mainnet", TargetKind: "wallet",
		Dossier: ActorDefenseDossier{Wallet: "creator", Network: "solana-mainnet", Evidence: []ActorDefenseEvidenceRecord{row}},
		FundingOrigin: ActorFundingOrigin{Status: "not_investigated", TrailStatus: "not_investigated"},
	})

	item := result.Items[5]
	if item.ID != "AC-06" || item.Status != ActorAcceptancePass || item.EvidenceState != "verified" {
		t.Fatalf("completed zero-match comparison must pass: %+v", item)
	}
	if !strings.Contains(item.Summary, "0 recipient") {
		t.Fatalf("zero-match result must be explicit: %s", item.Summary)
	}
}

func TestOperationalAcceptanceHashChangesWhenHolderSourceCompletes(t *testing.T) {
	observed := time.Date(2026, 7, 25, 18, 0, 0, 0, time.UTC)
	row := actorAcceptanceTestEvidence("creator", "recipient", "creator_recipient_in_window", "sig-recipient", 100, observed, "spl-token", 10, "mint-a")
	row.Metadata["matches_top_holder"] = false
	input := ActorAcceptanceInput{
		Wallet: "creator", Network: "solana-mainnet", TargetKind: "wallet",
		Dossier: ActorDefenseDossier{Wallet: "creator", Network: "solana-mainnet", Evidence: []ActorDefenseEvidenceRecord{row}},
		FundingOrigin: ActorFundingOrigin{Status: "not_investigated", TrailStatus: "not_investigated"},
	}
	before := EvaluateOperationalActorAcceptance(input)
	input.Dossier.Evidence[0].Metadata["top_holder_status"] = "verified_role_resolution"
	after := EvaluateOperationalActorAcceptance(input)
	if before.AcceptanceHash == after.AcceptanceHash {
		t.Fatal("collector completion must change the canonical acceptance identity")
	}
}
