package defense

import (
	"encoding/base64"
	"strings"
	"testing"
)

func TestEvaluateDefenseValidationV02ValidatesExactControlConfiguration(t *testing.T) {
	report, err := EvaluateDefenseValidationV02(validDefenseValidationV02TestInput())
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != DefenseValidationVerdictValidatedV02 || report.ReportHash == "" || report.MainnetTransactionSent || report.VerdictAuthority {
		t.Fatalf("unexpected validation report: %+v", report)
	}
	counts := report.Controls[0].Counts
	if counts.AttackCases != 1 || counts.BenignCases != 1 || counts.CaughtInTime != 1 || counts.Clean != 1 {
		t.Fatalf("unexpected counts: %+v", counts)
	}
	attack := report.Controls[0].Cases[0]
	if attack.Outcome != DefenseValidationOutcomeCaughtInTimeV02 || attack.DetectionMS == nil || *attack.DetectionMS != 400 || attack.LeadTimeMS == nil || *attack.LeadTimeMS != 600 {
		t.Fatalf("unexpected attack result: %+v", attack)
	}
}

func TestEvaluateDefenseValidationV02FailsLateMissedAndFalsePositiveCases(t *testing.T) {
	tests := []struct {
		name    string
		mutate  func(*DefenseValidationInputV02)
		outcome string
		rule    string
	}{
		{"caught late", func(in *DefenseValidationInputV02) {
			late := int64(1200)
			in.Observations[0].AlertObservedOffsetMS = &late
		}, DefenseValidationOutcomeCaughtLateV02, defenseValidationRuleDetectionDeadlineV02},
		{"missed", func(in *DefenseValidationInputV02) {
			in.Observations[0].Status = DefenseValidationObservationNoAlertV02
			in.Observations[0].AlertObservedOffsetMS = nil
			in.Observations[0].AlertEvidenceRef = ""
			in.Observations[0].AlertEvidenceHash = ""
		}, DefenseValidationOutcomeMissedV02, defenseValidationRuleMissedAttackV02},
		{"false positive", func(in *DefenseValidationInputV02) {
			alert := int64(300)
			in.Observations[1].Status = DefenseValidationObservationAlertedV02
			in.Observations[1].AlertObservedOffsetMS = &alert
			in.Observations[1].AlertEvidenceRef = "alert:benign"
			in.Observations[1].AlertEvidenceHash = defenseValidationV02TestHash("7")
		}, DefenseValidationOutcomeFalsePositiveV02, defenseValidationRuleBenignControlV02},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validDefenseValidationV02TestInput()
			tt.mutate(&in)
			report, err := EvaluateDefenseValidationV02(in)
			if err != nil {
				t.Fatal(err)
			}
			if report.Verdict != DefenseValidationVerdictFailedV02 {
				t.Fatalf("failure not propagated: %+v", report)
			}
			for _, item := range report.Controls[0].Cases {
				if item.Outcome == tt.outcome && containsDefenseValidationV02String(item.TriggeredRules, tt.rule) {
					return
				}
			}
			t.Fatalf("expected outcome/rule missing: %+v", report.Controls[0].Cases)
		})
	}
}

func TestEvaluateDefenseValidationV02FailsClosedOnIncompleteEvidenceAndMatrix(t *testing.T) {
	in := validDefenseValidationV02TestInput()
	in.Observations[0].EvidenceState = DefenseValidationEvidenceObservedV02
	report, err := EvaluateDefenseValidationV02(in)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != DefenseValidationVerdictIncompleteV02 || report.Controls[0].Cases[0].Outcome != DefenseValidationOutcomeIncompleteV02 {
		t.Fatalf("unverified evidence did not fail closed: %+v", report)
	}

	in = validDefenseValidationV02TestInput()
	in.Cases, in.Observations = in.Cases[:1], in.Observations[:1]
	report, err = EvaluateDefenseValidationV02(in)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != DefenseValidationVerdictIncompleteV02 || !containsDefenseValidationV02String(report.Controls[0].TriggeredRules, defenseValidationRuleCompleteMatrixV02) {
		t.Fatalf("attack-only matrix was not incomplete: %+v", report)
	}
}

func TestEvaluateDefenseValidationV02ReportHashIsOrderIndependent(t *testing.T) {
	in := validDefenseValidationV02TestInput()
	first, err := EvaluateDefenseValidationV02(in)
	if err != nil {
		t.Fatal(err)
	}
	in.Cases[0], in.Cases[1] = in.Cases[1], in.Cases[0]
	in.Observations[0], in.Observations[1] = in.Observations[1], in.Observations[0]
	in.RunRef = "KDVR2-repeat-run"
	in.Cases[0].ExecutionRef, in.Cases[1].ExecutionRef = "execution:benign-repeat", "execution:attack-repeat"
	in.Observations[0].ObservationEvidenceRef, in.Observations[1].ObservationEvidenceRef = "observation:benign-repeat", "observation:attack-repeat"
	in.Observations[1].AlertEvidenceRef = "alert:attack-repeat"
	second, err := EvaluateDefenseValidationV02(in)
	if err != nil {
		t.Fatal(err)
	}
	if first.ReportHash != second.ReportHash {
		t.Fatalf("run-local ordering/refs changed report hash: %s != %s", first.ReportHash, second.ReportHash)
	}
	in.Controls[0].ConfigurationHash = defenseValidationV02TestHash("a")
	for i := range in.Cases {
		in.Cases[i].ControlConfigurationHash = in.Controls[0].ConfigurationHash
	}
	third, err := EvaluateDefenseValidationV02(in)
	if err != nil {
		t.Fatal(err)
	}
	if third.ReportHash == second.ReportHash {
		t.Fatal("configuration change did not change report hash")
	}
}

func TestEvaluateDefenseValidationV02RequiresScenarioAndExactControlBindings(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DefenseValidationInputV02)
		want   string
	}{
		{"missing scenario hash", func(in *DefenseValidationInputV02) { in.ScenarioContractHash = "" }, "scenario contract hash"},
		{"missing case scenario", func(in *DefenseValidationInputV02) { in.Cases[0].ScenarioContractHash = "" }, "scenario contract"},
		{"missing case control", func(in *DefenseValidationInputV02) { in.Cases[0].ControlRef = "" }, "control configuration"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := validDefenseValidationV02TestInput()
			tt.mutate(&input)
			if _, err := EvaluateDefenseValidationV02(input); err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q error, got %v", tt.want, err)
			}
		})
	}
}

func TestEvaluateDefenseValidationV02DoesNotReuseCasesAcrossControls(t *testing.T) {
	input := validDefenseValidationV02TestInput()
	input.Controls = append(input.Controls, DefenseValidationControlV02{
		ControlRef: "control:unexercised", AdapterVersion: "v0.2.0", ConfigurationHash: defenseValidationV02TestHash("a"),
		CollectorRef: "collector:unexercised", CollectorPublicKey: defenseValidationV02TestPublicKey(0x22),
	})
	report, err := EvaluateDefenseValidationV02(input)
	if err != nil {
		t.Fatal(err)
	}
	if report.Verdict != DefenseValidationVerdictIncompleteV02 || len(report.Controls) != 2 {
		t.Fatalf("unexercised control did not fail closed: %#v", report)
	}
	for _, control := range report.Controls {
		if control.ControlRef == "control:unexercised" && (len(control.Cases) != 0 || control.Counts.AttackCases != 0 || control.Counts.BenignCases != 0) {
			t.Fatalf("cases from another control were reused: %#v", control)
		}
	}
}

func TestEvaluateDefenseValidationV02UsesScenarioDetectionDeadline(t *testing.T) {
	input := validDefenseValidationV02TestInput()
	deadline, alert := int64(500), int64(600)
	input.Cases[0].DetectionDeadlineMS = &deadline
	input.Observations[0].AlertObservedOffsetMS = &alert
	report, err := EvaluateDefenseValidationV02(input)
	if err != nil {
		t.Fatal(err)
	}
	attack := report.Controls[0].Cases[0]
	if attack.Outcome != DefenseValidationOutcomeCaughtLateV02 || attack.LeadTimeMS == nil || *attack.LeadTimeMS != -100 {
		t.Fatalf("stricter scenario detection deadline was not enforced: %#v", attack)
	}
}

func TestEvaluateDefenseValidationV02RejectsUnsafeOrAmbiguousInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*DefenseValidationInputV02)
		want   string
	}{
		{"mainnet", func(in *DefenseValidationInputV02) { in.Cases[0].MainnetTransactionSent = true }, "no-mainnet"},
		{"duplicate observation", func(in *DefenseValidationInputV02) { in.Observations = append(in.Observations, in.Observations[0]) }, "duplicate observation"},
		{"collector mismatch", func(in *DefenseValidationInputV02) { in.Observations[0].CollectorRef = "collector:unbound" }, "collector does not match"},
		{"self attestation", func(in *DefenseValidationInputV02) { in.Controls[0].CollectorRef = in.Controls[0].ControlRef }, "own independent collector"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			in := validDefenseValidationV02TestInput()
			tt.mutate(&in)
			_, err := EvaluateDefenseValidationV02(in)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected error containing %q, got %v", tt.want, err)
			}
		})
	}
}

func validDefenseValidationV02TestInput() DefenseValidationInputV02 {
	impact, detectionDeadline, alert := int64(1000), int64(1000), int64(400)
	scenarioHash := defenseValidationV02TestHash("0")
	controlHash := defenseValidationV02TestHash("1")
	return DefenseValidationInputV02{
		RunRef: "KDVR2-run", ScenarioRef: "scenario:safe-intent-mutation", ScenarioVersion: "v1.0.0", ScenarioContractHash: scenarioHash, Chain: "evm", RulesetVersion: DefenseValidationRulesetVersionV02,
		Controls: []DefenseValidationControlV02{{ControlRef: "control:execution-proof", AdapterVersion: "v0.2.0", ConfigurationHash: controlHash, CollectorRef: "collector:koschei-independent", CollectorPublicKey: defenseValidationV02TestPublicKey(0x11)}},
		Cases: []DefenseValidationCaseV02{
			{CaseRef: "case:attack", CaseKind: DefenseValidationCaseAttackV02, TechniqueID: "KOSCHEI:SAFE-INTENT-MUTATION", ControlRef: "control:execution-proof", ControlConfigurationHash: controlHash, ScenarioRef: "scenario:safe-intent-mutation", ScenarioVersion: "v1.0.0", ScenarioContractHash: scenarioHash, ExecutionMode: DefenseValidationExecutionForkV02, ExecutionRef: "execution:attack", ExecutionHash: defenseValidationV02TestHash("2"), PreStateHash: defenseValidationV02TestHash("3"), PostStateHash: defenseValidationV02TestHash("4"), EvidenceState: DefenseValidationEvidenceVerifiedV02, ImpactOffsetMS: &impact, DetectionDeadlineMS: &detectionDeadline, ObservationWindowMS: 2000},
			{CaseRef: "case:benign", CaseKind: DefenseValidationCaseBenignV02, TechniqueID: "BENIGN:AUTHORIZED-SAFE-TRANSFER", ControlRef: "control:execution-proof", ControlConfigurationHash: controlHash, ScenarioRef: "scenario:safe-intent-mutation", ScenarioVersion: "v1.0.0", ScenarioContractHash: scenarioHash, ExecutionMode: DefenseValidationExecutionSandboxV02, ExecutionRef: "execution:benign", ExecutionHash: defenseValidationV02TestHash("5"), PreStateHash: defenseValidationV02TestHash("3"), PostStateHash: defenseValidationV02TestHash("6"), EvidenceState: DefenseValidationEvidenceVerifiedV02, ObservationWindowMS: 2000},
		},
		Observations: []DefenseValidationObservationV02{
			{ControlRef: "control:execution-proof", CollectorRef: "collector:koschei-independent", CaseRef: "case:attack", Status: DefenseValidationObservationAlertedV02, ObservationEvidenceRef: "observation:attack", ObservationEvidenceHash: defenseValidationV02TestHash("8"), AlertObservedOffsetMS: &alert, AlertEvidenceRef: "alert:attack", AlertEvidenceHash: defenseValidationV02TestHash("7"), ObservationCompletedOffsetMS: 2000, EvidenceState: DefenseValidationEvidenceVerifiedV02},
			{ControlRef: "control:execution-proof", CollectorRef: "collector:koschei-independent", CaseRef: "case:benign", Status: DefenseValidationObservationNoAlertV02, ObservationEvidenceRef: "observation:benign", ObservationEvidenceHash: defenseValidationV02TestHash("9"), ObservationCompletedOffsetMS: 2000, EvidenceState: DefenseValidationEvidenceVerifiedV02},
		},
	}
}

func defenseValidationV02TestPublicKey(fill byte) string {
	key := make([]byte, 32)
	for i := range key {
		key[i] = fill
	}
	return base64.RawURLEncoding.EncodeToString(key)
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
