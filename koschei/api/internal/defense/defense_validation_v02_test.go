package defense

import (
	"strings"
	"testing"
)

func TestEvaluateDefenseValidationV02ValidatesExactControlConfiguration(t *testing.T) {
	input := validDefenseValidationV02TestInput()
	report, err := EvaluateDefenseValidationV02(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != DefenseValidationVerdictValidatedV02 || report.ReportHash == "" || report.RulesetVersion != DefenseValidationRulesetVersionV02 {
		t.Fatalf("unexpected validation report: %+v", report)
	}
	if report.MainnetTransactionSent || report.VerdictAuthority {
		t.Fatalf("validation report crossed an authority boundary: %+v", report)
	}
	if len(report.Controls) != 1 || report.Controls[0].Verdict != DefenseValidationVerdictValidatedV02 {
		t.Fatalf("unexpected control result: %+v", report.Controls)
	}
	counts := report.Controls[0].Counts
	if counts.AttackCases != 1 || counts.BenignCases != 1 || counts.CaughtInTime != 1 || counts.Clean != 1 {
		t.Fatalf("unexpected exact counts: %+v", counts)
	}
	attack := report.Controls[0].Cases[0]
	if attack.Outcome != DefenseValidationOutcomeCaughtInTimeV02 || attack.DetectionMS == nil || *attack.DetectionMS != 400 || attack.LeadTimeMS == nil || *attack.LeadTimeMS != 600 {
		t.Fatalf("unexpected attack timing result: %+v", attack)
	}
}

func TestEvaluateDefenseValidationV02FailsLateMissedAndFalsePositiveCases(t *testing.T) {
	tests := []struct {
		name            string
		mutate          func(*DefenseValidationInputV02)
		expectedOutcome string
		expectedRule    string
	}{
		{
			name: "caught late",
			mutate: func(input *DefenseValidationInputV02) {
				late := int64(1200)
				input.Observations[0].AlertObservedOffsetMS = &late
			},
			expectedOutcome: DefenseValidationOutcomeCaughtLateV02,
			expectedRule: defenseValidationRuleDetectionDeadlineV02,
		},
		{
			name: "missed",
			mutate: func(input *DefenseValidationInputV02) {
				input.Observations[0].Status = DefenseValidationObservationNoAlertV02
				input.Observations[0].AlertObservedOffsetMS = nil
				input.Observations[0].AlertEvidenceRef = ""
				input.Observations[0].AlertEvidenceHash = ""
			},
			expectedOutcome: DefenseValidationOutcomeMissedV02,
			expectedRule: defenseValidationRuleMissedAttackV02,
		},
		{
			name: "false positive",
			mutate: func(input *DefenseValidationInputV02) {
				alerted := int64(300)
				input.Observations[1].Status = DefenseValidationObservationAlertedV02
				input.Observations[1].AlertObservedOffsetMS = &alerted
				input.Observations[1].AlertEvidenceRef = "alert:benign"
				input.Observations[1].AlertEvidenceHash = defenseValidationV02TestHash("7")
			},
			expectedOutcome: DefenseValidationOutcomeFalsePositiveV02,
			expectedRule: defenseValidationRuleBenignControlV02,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := validDefenseValidationV02TestInput()
			test.mutate(&input)
			report, err := EvaluateDefenseValidationV02(input)
			if err != nil {
				t.Fatal(err)
			}
			if report.Verdict != DefenseValidationVerdictFailedV02 || report.Controls[0].Verdict != DefenseValidationVerdictFailedV02 {
				t.Fatalf("failure was not propagated: %+v", report)
			}
			found := false
			for _, item := range report.Controls[0].Cases {
				if item.Outcome == test.expectedOutcome {
					found = true
					if !containsDefenseValidationV02String(item.TriggeredRules, test.expectedRule) {
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

func TestEvaluateDefenseValidationV02FailsClosedOnIncompleteEvidence(t *testing.T) {
	input := validDefenseValidationV02TestInput()
	input.Observations[0].EvidenceState = DefenseValidationEvidenceObservedV02
	report, err := EvaluateDefenseValidationV02(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != DefenseValidationVerdictIncompleteV02 || report.Controls[0].Verdict != DefenseValidationVerdictIncompleteV02 {
		t.Fatalf("unverified observation did not fail closed: %+v", report)
	}
	if report.Controls[0].Cases[0].Outcome != DefenseValidationOutcomeIncompleteV02 || !containsDefenseValidationV02String(report.Controls[0].Cases[0].TriggeredRules, defenseValidationRuleIndependentAlertV02) {
		t.Fatalf("incomplete evidence reason was lost: %+v", report.Controls[0].Cases[0])
	}
}

func TestEvaluateDefenseValidationV02RequiresAttackAndBenignMatrix(t *testing.T) {
	input := validDefenseValidationV02TestInput()
	input.Cases = input.Cases[:1]
	input.Observations = input.Observations[:1]
	report, err := EvaluateDefenseValidationV02(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != DefenseValidationVerdictIncompleteV02 || report.Controls[0].Verdict != DefenseValidationVerdictIncompleteV02 || !containsDefenseValidationV02String(report.Controls[0].TriggeredRules, defenseValidationRuleCompleteMatrixV02) {
		t.Fatalf("attack-only matrix was not incomplete: %+v", report)
	}
}

func TestEvaluateDefenseValidationV02IsOrderIndependent(t *testing.T) {
	input := validDefenseValidationV02TestInput()
	first, err := EvaluateDefenseValidationV02(input)
	if err != nil {
		t.Fatal(err)
	}

	input.Cases[0], input.Cases[1] = input.Cases[1], input.Cases[0]
	input.Observations[0], input.Observations[1] = input.Observations[1], input.Observations[0]
	input.RunRef = "KDVR2-repeat-run"
	input.Cases[0].ExecutionRef = "execution:benign-repeat"
	input.Cases[1].ExecutionRef = "execution:attack-repeat"
	input.Observations[0].ObservationEvidenceRef = "observation:benign-repeat"
	input.Observations[1].ObservationEvidenceRef = "observation:attack-repeat"
	input.Observations[1].AlertEvidenceRef = "alert:attack-repeat"

	second, err := EvaluateDefenseValidationV02(input)
	if err != nil {
		t.Fatal(err)
	}
	if first.ReportHash != second.ReportHash {
		t.Fatalf("input order or run-local refs changed report identity: first=%s second=%s", first.ReportHash, second.ReportHash)
	}

	input.Controls[0].ConfigurationHash = defenseValidationV02TestHash("a")
	third, err := EvaluateDefenseValidationV02(input)
	if err != nil {
		t.Fatal(err)
	}
	if third.ReportHash == second.ReportHash {
		t.Fatal("control configuration change did not change report identity")
	}
}

func TestEvaluateDefenseValidationV02RejectsMainnetAndAmbiguousObservations(t *testing.T) {
	input := validDefenseValidationV02TestInput()
	input.Cases[0].MainnetTransactionSent = true
	if _, err := EvaluateDefenseValidationV02(input); err == nil || !strings.Contains(err.Error(), "no-mainnet") {
		t.Fatalf("mainnet execution was not rejected: %v", err)
	}

	input = validDefenseValidationV02TestInput()
	input.Observations = append(input.Observations, input.Observations[0])
	if _, err := EvaluateDefenseValidationV02(input); err == nil || !strings.Contains(err.Error(), "duplicate observation") {
		t.Fatalf("duplicate observation was not rejected: %v", err)
	}

	input = validDefenseValidationV02TestInput()
	input.Observations[0].CollectorRef = "collector:unbound"
	if _, err := EvaluateDefenseValidationV02(input); err == nil || !strings.Contains(err.Error(), "collector does not match") {
		t.Fatalf("unbound collector observation was not rejected: %v", err)
	}

	input = validDefenseValidationV02TestInput()
	input.Controls[0].CollectorRef = input.Controls[0].ControlRef
	if _, err := EvaluateDefenseValidationV02(input); err == nil || !strings.Contains(err.Error(), "own independent collector") {
		t.Fatalf("self-attesting control was not rejected: %v", err)
	}
}

func validDefenseValidationV02TestInput() DefenseValidationInputV02 {
	impact := int64(1000)
	alerted := int64(400)
	return DefenseValidationInputV02{
		RunRef: "KDVR2-run",
		ScenarioRef: "scenario:safe-intent-mutation",
		ScenarioVersion: "v1.0.0",
		Chain: "evm",
		RulesetVersion: DefenseValidationRulesetVersionV02,
		Controls: []DefenseValidationControlV02{
			{
				ControlRef: "control:execution-proof",
				AdapterVersion: "v0.2.0",
				ConfigurationHash: defenseValidationV02TestHash("1"),
				CollectorRef: "collector:koschei-independent",
			},
		},
		Cases: []DefenseValidationCaseV02{
			{
				CaseRef: "case:attack",
				CaseKind: DefenseValidationCaseAttackV02,
				TechniqueID: "KOSCHEI:SAFE-INTENT-MUTATION",
				ExecutionMode: DefenseValidationExecutionForkV02,
				ExecutionRef: "execution:attack",
				ExecutionHash: defenseValidationV02TestHash("2"),
				PreStateHash: defenseValidationV02TestHash("3"),
				PostStateHash: defenseValidationV02TestHash("4"),
				EvidenceState: DefenseValidationEvidenceVerifiedV02,
				ImpactOffsetMS: &impact,
				ObservationWindowMS: 2000,
				MainnetTransactionSent: false,
			},
			{
				CaseRef: "case:benign",
				CaseKind: DefenseValidationCaseBenignV02,
				TechniqueID: "BENIGN:AUTHORIZED-SAFE-TRANSFER",
				ExecutionMode: DefenseValidationExecutionSandboxV02,
				ExecutionRef: "execution:benign",
				ExecutionHash: defenseValidationV02TestHash("5"),
				PreStateHash: defenseValidationV02TestHash("3"),
				PostStateHash: defenseValidationV02TestHash("6"),
				EvidenceState: DefenseValidationEvidenceVerifiedV02,
				ObservationWindowMS: 2000,
				MainnetTransactionSent: false,
			},
		},
		Observations: []DefenseValidationObservationV02{
			{
				ControlRef: "control:execution-proof",
				CollectorRef: "collector:koschei-independent",
				CaseRef: "case:attack",
				Status: DefenseValidationObservationAlertedV02,
				ObservationEvidenceRef: "observation:attack",
				ObservationEvidenceHash: defenseValidationV02TestHash("8"),
				AlertObservedOffsetMS: &alerted,
				AlertEvidenceRef: "alert:attack",
				AlertEvidenceHash: defenseValidationV02TestHash("7"),
				ObservationCompletedOffsetMS: 2000,
				EvidenceState: DefenseValidationEvidenceVerifiedV02,
			},
			{
				ControlRef: "control:execution-proof",
				CollectorRef: "collector:koschei-independent",
				CaseRef: "case:benign",
				Status: DefenseValidationObservationNoAlertV02,
				ObservationEvidenceRef: "observation:benign",
				ObservationEvidenceHash: defenseValidationV02TestHash("9"),
				ObservationCompletedOffsetMS: 2000,
				EvidenceState: DefenseValidationEvidenceVerifiedV02,
			},
		},
	}
}

func defenseValidationV02TestHash(character string) string {
	return "sha256:" + strings.Repeat(character, 64)
}

func containsDefenseValidationV02String(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
