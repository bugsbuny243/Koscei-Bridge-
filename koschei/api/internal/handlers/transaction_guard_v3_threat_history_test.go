package handlers

import (
	"testing"
	"time"
)

func TestTransactionGuardV3ThreatCandidatesExtractsRecipientsDelegatesAndPrograms(t *testing.T) {
	wallet := "22222222222222222222222222222222"
	program := "33333333333333333333333333333333"
	recipient := "44444444444444444444444444444444"
	delegate := "55555555555555555555555555555555"
	decoded := transactionGuardDecodedTransaction{
		ProgramIDs: []string{guardV3SystemProgramID, program},
		SOLTransfers: []transactionGuardDecodedSOLTransfer{{Source: wallet, Recipient: recipient, Lamports: "10"}},
		TokenOperations: []transactionGuardDecodedTokenOperation{
			{Kind: "approve", Delegate: delegate, Source: "66666666666666666666666666666666", Authority: wallet, AmountRaw: "50"},
			{Kind: "transfer", Destination: recipient, Source: "77777777777777777777777777777777", Authority: wallet, AmountRaw: "5"},
		},
	}

	got := transactionGuardV3ThreatCandidates(decoded, wallet)
	roles := map[string][]string{}
	for _, candidate := range got {
		roles[candidate.Address] = candidate.Roles
	}
	if len(got) != 3 {
		t.Fatalf("candidate count=%d candidates=%#v", len(got), got)
	}
	if len(roles[program]) == 0 || len(roles[recipient]) != 2 || len(roles[delegate]) == 0 {
		t.Fatalf("roles=%#v", roles)
	}
	if _, exists := roles[guardV3SystemProgramID]; exists {
		t.Fatal("builtin system program entered threat-history candidates")
	}
	if _, exists := roles[wallet]; exists {
		t.Fatal("declared wallet entered its own threat-history candidates")
	}
}

func TestAggregateTransactionGuardThreatRowsCreatesCriticalFinding(t *testing.T) {
	address := "44444444444444444444444444444444"
	observed := time.Date(2026, 7, 31, 1, 2, 3, 0, time.UTC)
	analysis, findings := aggregateTransactionGuardThreatRows(
		[]transactionGuardThreatCandidate{{Address: address, Roles: []string{"sol_recipient"}}},
		[]transactionGuardThreatRow{{
			Target: address, TargetType: "wallet", ModuleID: "drain_recipient_detector",
			RiskIndex: 91, RiskLevel: "critical", Grade: "F", Verdict: "Prior critical recipient risk observed",
			Recommendation: "Do not interact", Evidence: []string{"Matched prior signed drain evidence"}, ObservedAt: observed,
		}},
		false,
	)
	if !analysis.Complete || !analysis.Available || analysis.SubjectsMatched != 1 {
		t.Fatalf("analysis=%#v", analysis)
	}
	if analysis.HighestRiskLevel != "critical" || analysis.HighestRiskIndex != 91 {
		t.Fatalf("highest=%s/%d", analysis.HighestRiskLevel, analysis.HighestRiskIndex)
	}
	if len(findings) != 1 || findings[0].Score != 75 || findings[0].Severity != "critical" {
		t.Fatalf("findings=%#v", findings)
	}
}

func TestAggregateTransactionGuardThreatRowsDoesNotPunishLowRiskHistory(t *testing.T) {
	address := "44444444444444444444444444444444"
	analysis, findings := aggregateTransactionGuardThreatRows(
		[]transactionGuardThreatCandidate{{Address: address, Roles: []string{"invoked_program"}}},
		[]transactionGuardThreatRow{{Target: address, ModuleID: "program_sentinel", RiskIndex: 8, RiskLevel: "low", ObservedAt: time.Now().UTC()}},
		false,
	)
	if analysis.SubjectsMatched != 1 {
		t.Fatalf("analysis=%#v", analysis)
	}
	if len(findings) != 0 {
		t.Fatalf("low-risk history produced findings=%#v", findings)
	}
}
