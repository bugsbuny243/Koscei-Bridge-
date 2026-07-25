package services

import (
	"strings"
	"testing"
	"time"
)

func TestEvaluateActorAcceptanceDeterministicCompleteCase(t *testing.T) {
	observed := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	wallet := "yHCxHBEaJW5tbndqC8JciSThr7U1cqLpdcsvHcx6PRe"
	evidence := []ActorDefenseEvidenceRecord{
		actorAcceptanceTestEvidence(wallet, "mint-a", "created_token", "sig-create-a", 100, observed, "pump.fun", 0, "mint-a"),
		actorAcceptanceTestEvidence(wallet, "mint-b", "created_token", "sig-create-b", 101, observed.Add(time.Minute), "pump.fun", 0, "mint-b"),
		actorAcceptanceTestEvidence(wallet, "recipient-a", "initial_token_recipient", "sig-recipient", 102, observed.Add(2*time.Minute), "spl-token", 250, "mint-a"),
		actorAcceptanceTestEvidence(wallet, "holder-a", "dominant_holder_reuse", "sig-holder", 103, observed.Add(3*time.Minute), "koschei-holder-index", 0, "mint-a"),
		actorAcceptanceTestEvidence(wallet, "pool-a", "liquidity_remove_activity", "sig-liquidity", 104, observed.Add(4*time.Minute), "raydium", 12, "mint-a"),
		actorAcceptanceTestEvidence(wallet, "holder-a", "direct_token_transfer_out", "sig-direct", 105, observed.Add(5*time.Minute), "spl-token", 5, "mint-a"),
	}
	evidence[2].Metadata["matches_top_holder"] = true
	evidence[2].Metadata["top_holder_rank"] = 1
	verdict := ActorDefenseRuleVerdict{
		Grade: "D", Verdict: "hard_trigger", RulesetVersion: ActorDefenseRulesetVersion,
		TriggeredRules: []ActorDefenseRuleHit{{
			RuleID: ActorRuleHardCreatorHolderFunding, EvidenceStatus: "verified", GradeCap: "D",
			EvidenceKeys: []string{evidence[5].EvidenceKey}, Signatures: []string{evidence[5].Signature},
		}},
		DecisionPath: []string{"VERIFIED hard trigger applied."}, Signed: true,
		Signature: "actor-verdict-signature",
	}
	input := ActorAcceptanceInput{
		Wallet: wallet, Network: "solana-mainnet", TargetKind: "wallet",
		Dossier: ActorDefenseDossier{
			Wallet: wallet, Network: "solana-mainnet", Evidence: evidence,
			Track: ActorDefenseTrack{CreatedTokenCount: 2, DominantHolderTokenCount: 2},
		},
		FundingOrigin: ActorFundingOrigin{
			Wallet: wallet, Status: "initial_funding_observed", HistoryComplete: true,
			SourceWallet: "funding-wallet", DestinationWallet: wallet, AmountSOL: 1.25,
			Signature: "sig-funding", Slot: 99, ObservedAt: observed.Add(-time.Minute),
			Program: "system", InstructionType: "transfer", VerificationStatus: "verified",
			TrailStatus: "source_wallet_observed", IdentityScope: "onchain_wallet_only",
		},
		Verdict: verdict,
	}

	first := EvaluateActorAcceptance(input)
	second := EvaluateActorAcceptance(input)
	if first.Status != ActorAcceptancePass || first.PassCount != 10 {
		t.Fatalf("expected complete acceptance, got status=%s pass=%d fail=%d not_investigated=%d", first.Status, first.PassCount, first.FailCount, first.NotInvestigatedCount)
	}
	if first.AcceptanceHash == "" || first.AcceptanceHash != second.AcceptanceHash {
		t.Fatalf("acceptance identity is not deterministic: %q != %q", first.AcceptanceHash, second.AcceptanceHash)
	}
	if !strings.Contains(first.Items[9].Summary, "Verdict: D") || !strings.Contains(first.Items[9].Summary, ActorDefenseRulesetVersion) {
		t.Fatalf("unexpected verdict summary: %s", first.Items[9].Summary)
	}
}

func TestEvaluateActorAcceptanceWithholdsIncompleteClaims(t *testing.T) {
	wallet := "wallet-a"
	result := EvaluateActorAcceptance(ActorAcceptanceInput{
		Wallet: wallet, Network: "solana-mainnet", TargetKind: "wallet",
		Dossier: ActorDefenseDossier{
			Wallet: wallet,
			Track: ActorDefenseTrack{CreatedTokenCount: 2, DominantHolderTokenCount: 2},
			Tokens: []ActorDefenseTokenObservation{{Mint: "mint-a", Roles: []string{"creator_deployer"}}},
			Evidence: []ActorDefenseEvidenceRecord{{
				ActorWallet: wallet, CounterpartID: "mint-a", Relation: "created_token",
				VerificationStatus: "observed", EvidenceKey: "incomplete-created-token",
			}},
		},
		FundingOrigin: ActorFundingOrigin{Wallet: wallet, Status: "rpc_unavailable", TrailStatus: "not_investigated", VerificationStatus: "unverified"},
		Verdict: ActorDefenseRuleVerdict{Grade: "-", Verdict: "no_grade_trigger", RulesetVersion: ActorDefenseRulesetVersion},
	})
	if result.Status != ActorAcceptanceFail {
		t.Fatalf("expected fail-closed acceptance, got %s", result.Status)
	}
	if result.Items[2].Status != ActorAcceptanceFail || result.Items[2].EvidenceState != "not_verified" {
		t.Fatalf("created-token observation must not pass without a complete evidence line: %+v", result.Items[2])
	}
	if result.Items[8].Status != ActorAcceptancePass || result.Items[8].EvidenceState != "not_verified" || result.Items[8].Summary != "Direct creator → dominant-holder relation: NOT VERIFIED" {
		t.Fatalf("direct relation must pass the explicit-withholding contract: %+v", result.Items[8])
	}
	if result.Items[9].Status != ActorAcceptanceFail {
		t.Fatalf("numberless no-grade verdict must not satisfy acceptance: %+v", result.Items[9])
	}
}

func TestActorAcceptanceDirectRelationRequiresVerifiedEvidence(t *testing.T) {
	observed := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	row := actorAcceptanceTestEvidence("creator", "holder", "direct_token_transfer_out", "sig", 10, observed, "spl-token", 1, "mint")
	row.VerificationStatus = "inferred"
	result := EvaluateActorAcceptance(ActorAcceptanceInput{
		Wallet: "creator", Network: "solana-mainnet", TargetKind: "wallet",
		Dossier: ActorDefenseDossier{Evidence: []ActorDefenseEvidenceRecord{row}},
		FundingOrigin: ActorFundingOrigin{Status: "not_investigated", TrailStatus: "not_investigated"},
	})
	if result.Items[8].Status != ActorAcceptancePass || result.Items[8].EvidenceState != "not_verified" {
		t.Fatalf("inferred direct relation must remain explicitly withheld: %+v", result.Items[8])
	}
}

func TestActorAcceptanceRejectsMissingProgramMetadata(t *testing.T) {
	observed := time.Date(2026, 7, 13, 12, 0, 0, 0, time.UTC)
	row := actorAcceptanceTestEvidence("creator", "mint", "created_token", "sig", 10, observed, "pump.fun", 0, "mint")
	delete(row.Metadata, "program")
	result := EvaluateActorAcceptance(ActorAcceptanceInput{
		Wallet: "creator", Network: "solana-mainnet", TargetKind: "wallet",
		Dossier: ActorDefenseDossier{
			Track: ActorDefenseTrack{CreatedTokenCount: 1},
			Tokens: []ActorDefenseTokenObservation{{Mint: "mint", Roles: []string{"creator_deployer"}}},
			Evidence: []ActorDefenseEvidenceRecord{row},
		},
		FundingOrigin: ActorFundingOrigin{Status: "not_investigated", TrailStatus: "not_investigated"},
	})
	if result.Items[2].Status != ActorAcceptanceFail || len(result.Items[2].Evidence) != 0 {
		t.Fatalf("missing program metadata must fail closed: %+v", result.Items[2])
	}
}

func actorAcceptanceTestEvidence(source, destination, relation, signature string, slot int64, observed time.Time, program string, amount float64, mint string) ActorDefenseEvidenceRecord {
	return ActorDefenseEvidenceRecord{
		Network: "solana-mainnet", ActorWallet: source, CounterpartKind: "wallet", CounterpartID: destination,
		Relation: relation, VerificationStatus: "verified", EvidenceKey: signature + ":" + relation,
		Source: "test_fixture", Signature: signature, Slot: slot, ObservedAt: observed,
		TokenMint: mint, TokenAmount: amount, OccurrenceCount: 1,
		Metadata: map[string]any{"source_wallet": source, "destination_wallet": destination, "program": program},
	}
}
