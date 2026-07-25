package services

import (
	"strings"
	"testing"
)

func TestOperationalAcceptanceAcceptsSignedDeterministicWithhold(t *testing.T) {
	track := ActorDefenseTrack{
		Network: "solana-mainnet", TargetKind: "wallet", TargetID: "ActorWallet",
		State: "correlated", RelatedActorCount: 1,
	}
	verdict := EvaluateEvidenceBoundActorDefenseRules(track, nil)
	if verdict.Grade != "-" || !verdict.Signed {
		t.Fatalf("precondition: expected signed WITHHOLD, got %#v", verdict)
	}

	result := EvaluateOperationalActorAcceptance(ActorAcceptanceInput{
		Wallet: "ActorWallet", Network: "solana-mainnet", TargetKind: "wallet",
		Dossier: ActorDefenseDossier{Wallet: "ActorWallet", Network: "solana-mainnet"},
		FundingOrigin: ActorFundingOrigin{Status: "not_investigated", TrailStatus: "not_investigated"},
		Verdict: verdict,
	})
	item := result.Items[9]
	if item.ID != "AC-10" || item.Status != ActorAcceptancePass || item.EvidenceState != "withheld" {
		t.Fatalf("signed WITHHOLD must satisfy deterministic verdict criterion: %+v", item)
	}
	if !strings.Contains(item.Summary, "WITHHOLD") || len(item.Evidence) != 1 {
		t.Fatalf("WITHHOLD acceptance must be explicit and signed: %+v", item)
	}
}

func TestOperationalAcceptanceRejectsUnsignedWithhold(t *testing.T) {
	result := EvaluateOperationalActorAcceptance(ActorAcceptanceInput{
		Wallet: "ActorWallet", Network: "solana-mainnet", TargetKind: "wallet",
		Dossier: ActorDefenseDossier{Wallet: "ActorWallet", Network: "solana-mainnet"},
		FundingOrigin: ActorFundingOrigin{Status: "not_investigated", TrailStatus: "not_investigated"},
		Verdict: ActorDefenseRuleVerdict{
			Grade: "-", Verdict: "watch_only", RulesetVersion: ActorDefenseRulesetVersion,
			DecisionPath: []string{"Only watch flags remain."}, Signed: false,
		},
	})
	item := result.Items[9]
	if item.Status != ActorAcceptanceFail {
		t.Fatalf("unsigned WITHHOLD must fail closed: %+v", item)
	}
}

func TestOperationalAcceptanceStillRequiresEvidenceForLetterGrade(t *testing.T) {
	result := EvaluateOperationalActorAcceptance(ActorAcceptanceInput{
		Wallet: "ActorWallet", Network: "solana-mainnet", TargetKind: "wallet",
		Dossier: ActorDefenseDossier{Wallet: "ActorWallet", Network: "solana-mainnet"},
		FundingOrigin: ActorFundingOrigin{Status: "not_investigated", TrailStatus: "not_investigated"},
		Verdict: ActorDefenseRuleVerdict{
			Grade: "B", Verdict: "compounding_rule", RulesetVersion: ActorDefenseRulesetVersion,
			Signed: true, Signature: "signature-without-rule-evidence",
		},
	})
	item := result.Items[9]
	if item.Status != ActorAcceptanceFail {
		t.Fatalf("letter grade without triggered rule evidence must fail: %+v", item)
	}
}
