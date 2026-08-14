package defense

import (
	"strings"
	"testing"
)

func TestEvaluateDefenseValidationValidatesExactControlConfiguration(t *testing.T) {
	input := validDefenseValidationTestInput()
	report, err := EvaluateDefenseValidation(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != DefenseValidationVerdictValidated || report.ReportHash == "" || report.RulesetVersion != DefenseValidationRulesetVersion {
		t.Fatalf("unexpected validation report: %+v", report)
	}
	if report.MainnetTransactionSent || report.VerdictAuthority {
		t.Fatalf("validation report crossed an authority boundary: %+v", report)
	}
	if len(report.Controls) != 1 || report.Controls[0].Verdict != DefenseValidationVerdictValidated {
		t.Fatalf("unexpected control result: %+v", report.Controls)
	}
	counts := report.Controls[0].Counts
	if counts.AttackCases != 1 || counts.BenignCases != 1 || counts.CaughtInTime != 1 || counts.Clean != 1 {
		t.Fatalf("unexpected exact counts: %+v", counts)
	}
	attack := report.Controls[0].Cases[0]
	if attack.Outcome != DefenseValidationOutcomeCaughtInTime || attack.DetectionMS == nil || *attack.DetectionMS != 400 || attack.LeadTimeMS == nil || *attack.LeadTimeMS != 600 {
		t.Fatalf("unexpected attack timing result: %+v", attack)
	}
	if len(attack.EvidenceRefs) != 3 || len(attack.EvidenceHashes) != 5 {
		t.Fatalf("report identity calculation mutated evidence: %+v", attack)
	}
}

func TestEvaluateDefenseValidationFailsLateMissedAndFalsePositiveCases(t *testing.T) {
	tests := []struct {
		name           string
		mutate         func(*DefenseValidationInput)
		expectedOutcome string
		expectedRule   string
	}{
		{
			name: "caught late",
			mutate: func(input *DefenseValidationInput) {
				late := int64(1200)
				input.Observations[0].AlertObservedOffsetMS = &late
			},
			expectedOutcome: DefenseValidationOutcomeCaughtLate,
			expectedRule: defenseValidationRuleDetectionDeadline,
		},
		{
			name: "missed",
			mutate: func(input *DefenseValidationInput) {
				input.Observations[0].Status = DefenseValidationObservationNoAlert
				input.Observations[0].AlertObservedOffsetMS = nil
				input.Observations[0].AlertEvidenceRef = ""
				input.Observations[0].AlertEvidenceHash = ""
			},
			expectedOutcome: DefenseValidationOutcomeMissed,
			expectedRule: defenseValidationRuleMissedAttack,
		},
		{
			name: "false positive",
			mutate: func(input *DefenseValidationInput) {
				alerted := int64(300)
				input.Observations[1].Status = DefenseValidationObservationAlerted
				input.Observations[1].AlertObservedOffsetMS = &alerted
				input.Observations[1].AlertEvidenceRef = "alert:benign"
				input.Observations[1].AlertEvidenceHash = defenseValidationTestHash("7")
			},
			expectedOutcome: DefenseValidationOutcomeFalsePositive,
			expectedRule: defenseValidationRuleBenignControl,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validDefenseValidationTestInput()
			test.mutate(&input)
			report, err := EvaluateDefenseValidation(input)
			if err != nil {
				t.Fatal(err)
			}
			if report.Verdict != DefenseValidationVerdictFailed || report.Controls[0].Verdict != DefenseValidationVerdictFailed {
				t.Fatalf("failure was not propagated: %+v", report)
			}
			found := false
			for _, item := range report.Controls[0].Cases {
				if item.Outcome == test.expectedOutcome {
					found = true
					if !containsDefenseValidationString(item.TriggeredRules, test.expectedRule) {
						t.Fatalf("outcome %q did not retain rule %q: %+v", item.Outcome, test.expectedRule, item)
					}
				}
			}
			if !found {
				t.Fatalf("expected outcome %q not found: %+v", test.expectedOutcome, report.Controls[0].Cases)
			}
		})
	}
}

func TestEvaluateDefenseValidationFailsClosedOnIncompleteEvidence(t *testing.T) {
	input := validDefenseValidationTestInput()
	input.Observations[0].EvidenceState = DefenseValidationEvidenceObserved
	report, err := EvaluateDefenseValidation(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != DefenseValidationVerdictIncomplete || report.Controls[0].Verdict != DefenseValidationVerdictIncomplete {
		t.Fatalf("unverified observation did not fail closed: %+v", report)
	}
	if report.Controls[0].Cases[0].Outcome != DefenseValidationOutcomeIncomplete || !containsDefenseValidationString(report.Controls[0].Cases[0].TriggeredRules, defenseValidationRuleIndependentAlert) {
		t.Fatalf("incomplete evidence reason was lost: %+v", report.Controls[0].Cases[0])
	}
}

func TestEvaluateDefenseValidationRequiresAttackAndBenignMatrix(t *testing.T) {
	input := validDefenseValidationTestInput()
	input.Cases = input.Cases[:1]
	input.Observations = input.Observations[:1]
	report, err := EvaluateDefenseValidation(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != DefenseValidationVerdictIncomplete || report.Controls[0].Verdict != DefenseValidationVerdictIncomplete || !containsDefenseValidationString(report.Controls[0].TriggeredRules, defenseValidationRuleCompleteMatrix) {
		t.Fatalf("attack-only matrix was not incomplete: %+v", report)
	}
}

func TestEvaluateDefenseValidationIsOrderIndependent(t *testing.T) {
	input := validDefenseValidationTestInput()
	first, err := EvaluateDefenseValidation(input)
	if err != nil {
		t.Fatal(err)
	}
	input.Cases[0], input.Cases[1] = input.Cases[1], input.Cases[0]
	input.Observations[0], input.Observations[1] = input.Observations[1], input.Observations[0]
	input.RunRef = "KDVR1-repeat-run"
	input.Cases[0].ExecutionRef = "execution:benign-repeat"
	input.Cases[1].ExecutionRef = "execution:attack-repeat"
	input.Observations[0].ObservationEvidenceRef = "observation:benign-repeat"
	input.Observations[1].ObservationEvidenceRef = "observation:attack-repeat"
	input.Observations[1].AlertEvidenceRef = "alert:attack-repeat"
	second, err := EvaluateDefenseValidation(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.ReportHash != second.ReportHash {
		t.Fatalf("input order changed the report identity: first=%s second=%s", first.ReportHash, second.ReportHash)
	}
	input.Controls[0].ConfigurationHash = defenseValidationTestHash("a")
	third, err := EvaluateDefenseValidation(input)
	if err != nil {
		t.Fatal(err)
	}
	if third.ReportHash == second.ReportHash {
		t.Fatal("control configuration change did not change report identity")
	}
}

func TestEvaluateDefenseValidationRejectsMainnetAndAmbiguousObservations(t *testing.T) {
	input := validDefenseValidationTestInput()
	input.Cases[0].MainnetTransactionSent = true
	if _, err := EvaluateDefenseValidation(input); err == nil || !strings.Contains(err.Error(), "no-mainnet") {
		t.Fatalf("mainnet execution was not rejected: %v", err)
	}

	input = validDefenseValidationTestInput()
	input.Observations = append(input.Observations, input.Observations[0])
	if _, err := EvaluateDefenseValidation(input); err == nil || !strings.Contains(err.Error(), "duplicate observation") {
		t.Fatalf("duplicate observation was not rejected: %v", err)
	}

	input = validDefenseValidationTestInput()
	input.Observations[0].CollectorRef = "collector:unbound"
	if _, err := EvaluateDefenseValidation(input); err == nil || !strings.Contains(err.Error(), "collector does not match") {
		t.Fatalf("unbound collector observation was not rejected: %v", err)
	}
}

func validDefenseValidationTestInput() DefenseValidationInput {
	impact := int64(1000)
	alerted := int64(400)
	return DefenseValidationInput{
		RunRef: "KDVR1-run", ScenarioRef: "scenario:privileged-drain",
		ScenarioVersion: "v1.0.0", Chain: "solana",
		RulesetVersion: DefenseValidationRulesetVersion,
		Controls: []DefenseValidationControl{
			{
				ControlRef: "control:monitor-a", AdapterVersion: "v1.0.0",
				ConfigurationHash: defenseValidationTestHash("1"), CollectorRef: "collector:koschei-a",
			},
		},
		Cases: []DefenseValidationCase{
			{
				CaseRef: "case:attack", CaseKind: DefenseValidationCaseAttack,
				TechniqueID: "AADAPT:privileged-access", ExecutionMode: DefenseValidationExecutionFork,
				ExecutionRef: "execution:attack", ExecutionHash: defenseValidationTestHash("2"),
				PreStateHash: defenseValidationTestHash("3"), PostStateHash: defenseValidationTestHash("4"),
				EvidenceState: DefenseValidationEvidenceVerified, ImpactOffsetMS: &impact,
				ObservationWindowMS: 2000, MainnetTransactionSent: false,
			},
			{
				CaseRef: "case:benign", CaseKind: DefenseValidationCaseBenign,
				TechniqueID: "BENIGN:authorized-withdrawal", ExecutionMode: DefenseValidationExecutionSandbox,
				ExecutionRef: "execution:benign", ExecutionHash: defenseValidationTestHash("5"),
				PreStateHash: defenseValidationTestHash("3"), PostStateHash: defenseValidationTestHash("6"),
				EvidenceState: DefenseValidationEvidenceVerified,
				ObservationWindowMS: 2000, MainnetTransactionSent: false,
			},
		},
		Observations: []DefenseValidationObservation{
			{
				ControlRef: "control:monitor-a", CollectorRef: "collector:koschei-a", CaseRef: "case:attack",
				ObservationEvidenceRef: "observation:attack", ObservationEvidenceHash: defenseValidationTestHash("8"),
				Status: DefenseValidationObservationAlerted, AlertObservedOffsetMS: &alerted,
				AlertEvidenceRef: "alert:attack", AlertEvidenceHash: defenseValidationTestHash("7"),
				ObservationCompletedOffsetMS: 2000, EvidenceState: DefenseValidationEvidenceVerified,
			},
			{
				ControlRef: "control:monitor-a", CollectorRef: "collector:koschei-a", CaseRef: "case:benign",
				ObservationEvidenceRef: "observation:benign", ObservationEvidenceHash: defenseValidationTestHash("9"),
				Status: DefenseValidationObservationNoAlert,
				ObservationCompletedOffsetMS: 2000, EvidenceState: DefenseValidationEvidenceVerified,
			},
		},
	}
}

func defenseValidationTestHash(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

func containsDefenseValidationString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
