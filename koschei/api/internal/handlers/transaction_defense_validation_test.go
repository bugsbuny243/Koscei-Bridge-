package handlers

import "testing"

func TestTransactionDefenseValidationFailsOnProgramPolicyViolation(t *testing.T) {
	assessment := transactionFirewallAssessment{
		SimulationOK: true,
		ProgramIDs:   []string{"Allowed111", "Blocked111"},
	}
	programs := transactionGuardProgramPolicy{
		Invoked:        []string{"Allowed111", "Blocked111"},
		BlockedInvoked: []string{"Blocked111"},
		Complete:       false,
	}
	intent := transactionGuardIntentPolicy{
		Requested: true,
		Complete:  true,
		Accounts: []transactionGuardAccountDelta{{
			Address: "Account111",
			Role: "input",
			PolicyStatus: "pass",
			EvidenceStatus: "verified_rpc_simulation",
		}},
	}

	report := buildTransactionDefenseValidation(assessment, programs, intent)
	if report.Status != "fail" || report.Decision != "block" {
		t.Fatalf("expected fail/block, got %s/%s", report.Status, report.Decision)
	}
	check := defenseValidationCheckByID(report.Checks, "program_route_policy")
	if check.Status != "fail" {
		t.Fatalf("expected program policy failure, got %#v", check)
	}
	if !containsString(check.References.Programs, "Blocked111") {
		t.Fatalf("expected blocked program reference, got %#v", check.References)
	}
}

func TestTransactionDefenseValidationFailsOnGuardedStateDeltaViolation(t *testing.T) {
	assessment := transactionFirewallAssessment{SimulationOK: true, ProgramIDs: []string{"Program111"}}
	programs := transactionGuardProgramPolicy{Invoked: []string{"Program111"}, Complete: true}
	intent := transactionGuardIntentPolicy{
		Requested: true,
		Complete:  false,
		Accounts: []transactionGuardAccountDelta{{
			Address: "Vault111",
			Role: "input",
			PolicyStatus: "fail",
			EvidenceStatus: "verified_rpc_simulation",
		}},
	}

	report := buildTransactionDefenseValidation(assessment, programs, intent)
	if report.Status != "fail" || report.Decision != "block" {
		t.Fatalf("expected fail/block, got %s/%s", report.Status, report.Decision)
	}
	check := defenseValidationCheckByID(report.Checks, "state_delta_policy")
	if check.Status != "fail" || !containsString(check.References.Accounts, "Vault111") {
		t.Fatalf("expected concrete state-delta violation reference, got %#v", check)
	}
}

func TestTransactionDefenseValidationWithholdsWhenIntentPolicyMissing(t *testing.T) {
	assessment := transactionFirewallAssessment{SimulationOK: true, ProgramIDs: []string{"Program111"}, RiskIndex: 0}
	programs := transactionGuardProgramPolicy{Invoked: []string{"Program111"}, Complete: true}
	intent := transactionGuardIntentPolicy{Requested: false, Complete: true, Accounts: []transactionGuardAccountDelta{}}

	report := buildTransactionDefenseValidation(assessment, programs, intent)
	if report.Status != "insufficient_evidence" || report.Decision != "withhold" {
		t.Fatalf("expected insufficient_evidence/withhold, got %s/%s", report.Status, report.Decision)
	}
	check := defenseValidationCheckByID(report.Checks, "state_delta_policy")
	if check.Status != "insufficient_evidence" || len(check.RequiredEvidence) == 0 {
		t.Fatalf("expected missing state-delta policy to remain explicit, got %#v", check)
	}
}

func TestTransactionDefenseValidationDoesNotTrustLegacyNumericScore(t *testing.T) {
	assessment := transactionFirewallAssessment{
		SimulationOK: true,
		ProgramIDs:   []string{"Program111"},
		RiskIndex:    100,
		RiskLevel:    "critical",
		Action:       "block",
		Findings: []transactionFirewallFinding{{
			Code: "high_compute_usage",
			Severity: "medium",
			Title: "High compute usage",
			Evidence: "legacy numeric scoring signal",
			Score: 100,
		}},
	}
	programs := transactionGuardProgramPolicy{Invoked: []string{"Program111"}, Complete: true}
	intent := transactionGuardIntentPolicy{
		Requested: true,
		Complete:  true,
		Accounts: []transactionGuardAccountDelta{{
			Address: "Vault111",
			Role: "observe",
			PolicyStatus: "pass",
			EvidenceStatus: "verified_rpc_simulation",
		}},
	}

	report := buildTransactionDefenseValidation(assessment, programs, intent)
	if report.Status != "pass" || report.Decision != "pass" {
		t.Fatalf("legacy numeric score must not control defense validation, got %s/%s", report.Status, report.Decision)
	}
	if report.EvidencePolicy["numeric_score_authoritative"] || report.EvidencePolicy["legacy_firewall_score_authoritative"] {
		t.Fatalf("numeric score unexpectedly authoritative: %#v", report.EvidencePolicy)
	}
}

func TestTransactionDefenseValidationWithholdsSemanticSignalsUntilDecoded(t *testing.T) {
	assessment := transactionFirewallAssessment{
		SimulationOK: true,
		ProgramIDs:   []string{"Program111"},
		Findings: []transactionFirewallFinding{{
			Code: "authority_change",
			Severity: "high",
			Title: "Authority change",
			Evidence: "Instruction: SetAuthority",
			Score: 35,
		}},
	}
	programs := transactionGuardProgramPolicy{Invoked: []string{"Program111"}, Complete: true}
	intent := transactionGuardIntentPolicy{
		Requested: true,
		Complete:  true,
		Accounts: []transactionGuardAccountDelta{{Address: "Vault111", Role: "observe", PolicyStatus: "pass", EvidenceStatus: "verified_rpc_simulation"}},
	}

	report := buildTransactionDefenseValidation(assessment, programs, intent)
	if report.Status != "insufficient_evidence" || report.Decision != "withhold" {
		t.Fatalf("expected semantic signal to withhold pending decoded evidence, got %s/%s", report.Status, report.Decision)
	}
	check := defenseValidationCheckByID(report.Checks, "decoded_semantic_effects")
	if check.Status != "insufficient_evidence" || !containsString(check.References.EvidenceKeys, "authority_change") {
		t.Fatalf("expected authority signal evidence reference, got %#v", check)
	}
}

func defenseValidationCheckByID(checks []transactionDefenseValidationCheck, id string) transactionDefenseValidationCheck {
	for _, check := range checks {
		if check.ID == id {
			return check
		}
	}
	return transactionDefenseValidationCheck{}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
