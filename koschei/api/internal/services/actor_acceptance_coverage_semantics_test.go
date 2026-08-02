package services

import (
	"strings"
	"testing"
	"time"
)

func TestOperationalAcceptanceTreatsCompletedNegativeCollectorsAsPass(t *testing.T) {
	verdict := EvaluateEvidenceBoundActorDefenseRules(ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
	}, nil)
	dossier := ActorDefenseDossier{
		Wallet: "ActorWallet", Network: "solana-mainnet",
		Coverage: map[string]any{
			"acceptance_distribution": map[string]any{
				"status": "complete", "mints_discovered": 2, "mints_attempted": 2,
				"mints_completed": 2, "recipients_resolved": 0, "holder_comparisons": 0,
			},
			"acceptance_liquidity": map[string]any{
				"status":              "complete_no_explicit_liquidity_observed",
				"transactions_parsed": 25, "instructions_matched": 0,
			},
		},
	}
	result := EvaluateOperationalActorAcceptance(ActorAcceptanceInput{
		Wallet: "ActorWallet", Network: "solana-mainnet", TargetKind: "wallet",
		Dossier:       dossier,
		FundingOrigin: ActorFundingOrigin{Status: "not_investigated", TrailStatus: "not_investigated"},
		Verdict:       verdict,
	})
	for _, index := range []int{4, 5, 6, 7, 9} {
		if result.Items[index].Status != ActorAcceptancePass {
			t.Fatalf("%s should pass as completed positive/negative coverage: %+v", result.Items[index].ID, result.Items[index])
		}
	}
	if result.Items[4].EvidenceState != "not_observed" {
		t.Fatalf("AC-05 state=%q", result.Items[4].EvidenceState)
	}
	if result.Items[5].EvidenceState != "not_applicable" {
		t.Fatalf("AC-06 state=%q", result.Items[5].EvidenceState)
	}
	if result.Items[6].EvidenceState != "not_observed" {
		t.Fatalf("AC-07 state=%q", result.Items[6].EvidenceState)
	}
	if result.Items[7].EvidenceState != "not_observed" {
		t.Fatalf("AC-08 state=%q", result.Items[7].EvidenceState)
	}
}

func TestOperationalCrossTokenZeroCountersWithoutCollectorStatusRemainUninvestigated(t *testing.T) {
	item := operationalCrossTokenAcceptance(ActorDefenseDossier{
		Coverage: map[string]any{
			"acceptance_distribution": map[string]any{
				"mints_discovered": 0, "mints_completed": 0,
				"recipients_resolved": 0, "holder_comparisons": 0,
			},
		},
	})
	if item.Status != ActorAcceptanceNotInvestigated || item.EvidenceState != "not_investigated" {
		t.Fatalf("zero-valued counters without a completion status must not become not_applicable: %+v", item)
	}
}

func TestOperationalAcceptanceFailsPartialCollectorsWithReason(t *testing.T) {
	verdict := EvaluateEvidenceBoundActorDefenseRules(ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
	}, nil)
	dossier := ActorDefenseDossier{
		Wallet: "ActorWallet", Network: "solana-mainnet",
		Coverage: map[string]any{
			"acceptance_distribution": map[string]any{
				"status": "partial_timeout", "mints_discovered": 3, "mints_completed": 1,
				"limitations": []string{"Distribution enrichment time budget was exhausted."},
			},
			"acceptance_liquidity": map[string]any{
				"status": "rpc_failed", "limitations": []string{"Creator wallet signatures could not be fetched."},
			},
		},
	}
	result := EvaluateOperationalActorAcceptance(ActorAcceptanceInput{
		Wallet: "ActorWallet", Network: "solana-mainnet", TargetKind: "wallet",
		Dossier:       dossier,
		FundingOrigin: ActorFundingOrigin{Status: "not_investigated", TrailStatus: "not_investigated"},
		Verdict:       verdict,
	})
	for _, index := range []int{4, 6, 7} {
		if result.Items[index].Status != ActorAcceptanceFail {
			t.Fatalf("%s must fail when its worker ran but did not complete: %+v", result.Items[index].ID, result.Items[index])
		}
		if len(result.Items[index].Limitations) == 0 {
			t.Fatalf("%s must expose the technical reason", result.Items[index].ID)
		}
	}
}

func TestOperationalCrossTokenUsesTransactionBackedRecipientHolderRecurrence(t *testing.T) {
	observed := time.Date(2026, 7, 25, 20, 0, 0, 0, time.UTC)
	first := actorAcceptanceTestEvidence("creator", "holder-wallet", "initial_token_recipient", "sig-one", 101, observed, "spl-token", 100, "mint-one")
	first.Metadata["matches_top_holder"] = true
	first.Metadata["top_holder_status"] = "verified_role_resolution"
	second := actorAcceptanceTestEvidence("creator", "holder-wallet", "creator_recipient_in_window", "sig-two", 102, observed.Add(time.Minute), "spl-token", 200, "mint-two")
	second.Metadata["matches_top_holder"] = true
	second.Metadata["top_holder_status"] = "dominant_holder_role_unresolved"

	dossier := ActorDefenseDossier{
		Wallet: "creator", Network: "solana-mainnet", Evidence: []ActorDefenseEvidenceRecord{first, second},
		Coverage: map[string]any{
			"acceptance_distribution": map[string]any{
				"status": "complete", "mints_discovered": 2, "mints_completed": 2,
				"recipients_resolved": 2, "holder_comparisons": 2,
			},
		},
	}
	item := operationalCrossTokenAcceptance(dossier)
	if item.Status != ActorAcceptancePass || item.EvidenceState != "observed" || len(item.Evidence) != 2 {
		t.Fatalf("transaction-backed recurrence should pass AC-08: %+v", item)
	}
	if !strings.Contains(item.Summary, "2 creator mint") {
		t.Fatalf("summary must state the cross-token scope: %s", item.Summary)
	}
}

func TestOperationalLiquidityCompleteWithMissingPersistedRowFails(t *testing.T) {
	item := operationalLiquidityAcceptance(ActorDefenseDossier{
		Coverage: map[string]any{
			"acceptance_liquidity": map[string]any{"status": "complete_with_evidence", "evidence_persisted": 1},
		},
	})
	if item.Status != ActorAcceptanceFail || item.EvidenceState != "not_verified" {
		t.Fatalf("reported liquidity evidence absent from dossier must fail: %+v", item)
	}
}
