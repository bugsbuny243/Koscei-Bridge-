package handlers

import "testing"

func TestBuildTransactionGuardV3ExplanationSummarizesMovementsAndAuthorities(t *testing.T) {
	wallet := "22222222222222222222222222222222"
	recipient := "33333333333333333333333333333333"
	tokenSource := "44444444444444444444444444444444"
	tokenDestination := "55555555555555555555555555555555"
	mint := "66666666666666666666666666666666"
	delegate := "77777777777777777777777777777777"
	decimals := 2
	decoded := transactionGuardDecodedTransaction{
		Available: true, Complete: true,
		ProgramIDs: []string{"88888888888888888888888888888888"},
		SOLTransfers: []transactionGuardDecodedSOLTransfer{{Kind: "transfer", Source: wallet, Recipient: recipient, Lamports: "250000000"}},
		TokenOperations: []transactionGuardDecodedTokenOperation{
			{Kind: "transfer_checked", Source: tokenSource, Destination: tokenDestination, Mint: mint, Authority: wallet, AmountRaw: "500", Decimals: &decimals},
			{Kind: "approve_checked", Source: tokenSource, Delegate: delegate, Mint: mint, Authority: wallet, AmountRaw: "1000", Decimals: &decimals},
		},
		AutomaticBalance: transactionGuardAutomaticBalanceAnalysis{
			Requested: true, Available: true, Complete: true,
			WalletSOLSpentLamports: "1000000000",
			Accounts: []transactionGuardAutomaticBalanceDelta{{
				Address: tokenSource, TokenAccount: true, Mint: mint,
				PreTokenOwner: wallet, PostTokenOwner: wallet, TokenDeltaRaw: "-500", Changed: true,
			}},
		},
		SignedIntent: transactionGuardV3SignedIntentAssessment{Requested: true, Complete: true},
	}
	threat := transactionGuardThreatHistoryAnalysis{
		Requested: true, Available: true, Complete: true, Status: "matches_observed", SubjectsMatched: 1,
		Subjects: []transactionGuardThreatSubject{{Address: recipient, Roles: []string{"sol_recipient"}, Matched: true, HighestRiskLevel: "high", HighestRiskIndex: 70}},
	}
	assessment := transactionFirewallAssessment{
		Action: "block", RiskLevel: "critical", RiskIndex: 93,
		Findings: []transactionFirewallFinding{{Code: "historical_risk_match", Severity: "critical", Title: "Historical risk", Evidence: recipient, Score: 75}},
	}

	got := buildTransactionGuardV3Explanation(wallet, assessment, decoded, threat)
	if !got.Available || got.Action != "block" || got.EvidenceStatus != "complete" {
		t.Fatalf("explanation=%#v", got)
	}
	if len(got.Sends) < 3 {
		t.Fatalf("expected SOL, token and residual SOL movements, sends=%#v", got.Sends)
	}
	if len(got.Authorities) != 1 || got.Authorities[0].Delegate != delegate || !got.Authorities[0].Persistent {
		t.Fatalf("authorities=%#v", got.Authorities)
	}
	if len(got.Recipients) == 0 || !recipientHasHistoricalMatch(got.Recipients, recipient) {
		t.Fatalf("recipients=%#v", got.Recipients)
	}
	if len(got.Reasons) != 1 || got.Reasons[0].Code != "historical_risk_match" {
		t.Fatalf("reasons=%#v", got.Reasons)
	}
}

func TestFormatGuardRawAmount(t *testing.T) {
	decimals := 6
	cases := map[string]string{
		"0":       "0",
		"1":       "0.000001",
		"1000000": "1",
		"1234500": "1.2345",
	}
	for raw, expected := range cases {
		if got := formatGuardRawAmount(raw, &decimals); got != expected {
			t.Fatalf("raw=%s got=%s expected=%s", raw, got, expected)
		}
	}
}

func recipientHasHistoricalMatch(values []transactionGuardExplanationRecipient, address string) bool {
	for _, value := range values {
		if value.Address == address && value.HistoricalMatch && value.HistoricalRisk == "high" {
			return true
		}
	}
	return false
}
