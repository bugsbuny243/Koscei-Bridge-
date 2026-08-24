package defense

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestDefenseValidationScenarioContractV02AcceptsRepositoryScenarios(t *testing.T) {
	for _, name := range []string{"safe-intent-mutation-v1.json", "unauthorized-source-account-v1.json"} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join("..", "..", "..", "..", "docs", "defense-validation", "scenarios", name)
			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("read scenario: %v", err)
			}
			scenario, err := ParseDefenseValidationScenarioV02(data)
			if err != nil {
				t.Fatalf("parse scenario: %v", err)
			}
			if scenario.Contract != DefenseValidationScenarioContractV02 {
				t.Fatalf("contract=%q", scenario.Contract)
			}
			if scenario.RulesetVersion != DefenseValidationRulesetVersionV02 {
				t.Fatalf("ruleset=%q", scenario.RulesetVersion)
			}
		})
	}
}

func TestDefenseValidationScenarioContractV02RejectsUnsafeClaimBoundary(t *testing.T) {
	deadline := int64(1000)
	scenario := DefenseValidationScenarioV02{
		Contract:        DefenseValidationScenarioContractV02,
		ScenarioRef:     "scenario:test:unsafe",
		ScenarioVersion: "v1.0.0",
		Title:           "unsafe",
		Status:          "planned",
		Chain:           "sandbox",
		RulesetVersion:  DefenseValidationRulesetVersionV02,
		ClaimBoundary:   DefenseValidationScenarioClaimBoundaryV02{ProductionClaimAllowed: true},
		Environment:     DefenseValidationScenarioEnvironmentV02{ExecutionMode: "isolated_sandbox", OwnerApprovalRequired: true, DefaultOff: true},
		ControlContract: DefenseValidationScenarioControlContractV02{ControlClass: "test", CandidateControl: "test", IndependentCollectorRequired: true, AdapterVersionRequired: true, ConfigurationHashRequired: true, ProductionWiringRequiredForProductionClaim: true},
		Matrix: DefenseValidationScenarioMatrixV02{
			PairRef: "pair:test", MatchedFields: []string{"operation"}, SingleSecurityDifference: "authority",
			Cases: []DefenseValidationScenarioCaseV02{
				{CaseRef: "attack", CaseKind: DefenseValidationCaseAttackV02, Description: "attack", ImpactDeadlineMS: &deadline, ObservationWindowMS: 3000, ExpectedControlBehavior: DefenseValidationScenarioExpectedBehaviorV02{BlockOrAlertRequired: true, LatestDetectionOffsetMS: &deadline}},
				{CaseRef: "benign", CaseKind: DefenseValidationCaseBenignV02, Description: "benign", ObservationWindowMS: 3000, ExpectedControlBehavior: DefenseValidationScenarioExpectedBehaviorV02{FalsePositiveForbidden: true}},
			},
		},
		RequiredRunEvidence: []string{"runner_identity_hash", "pre_state_hash", "post_state_hash", "independent_observation_hash", "control_configuration_hash", "completed_observation_window"},
		AcceptanceGate:      map[string]any{"test": true},
		Limitations:         []string{"test"},
	}
	if err := ValidateDefenseValidationScenarioV02(scenario); err == nil {
		t.Fatal("unsafe production claim boundary accepted")
	}
}

func TestDefenseValidationScenarioContractV02RejectsNonIsolatedExecutionModes(t *testing.T) {
	for _, mode := range []string{"mainnet", "production", "live_rpc"} {
		t.Run(mode, func(t *testing.T) {
			scenario := readDefenseValidationScenarioFixtureV02(t, "unauthorized-source-account-v1.json")
			scenario.Environment.ExecutionMode = mode
			if err := ValidateDefenseValidationScenarioV02(scenario); err == nil {
				t.Fatalf("unsafe execution mode %q was accepted", mode)
			}
		})
	}
}

func TestDefenseValidationScenarioContractV02RejectsNegativeDetectionOffset(t *testing.T) {
	scenario := readDefenseValidationScenarioFixtureV02(t, "unauthorized-source-account-v1.json")
	negative := int64(-1)
	scenario.Matrix.Cases[0].ExpectedControlBehavior.LatestDetectionOffsetMS = &negative
	if err := ValidateDefenseValidationScenarioV02(scenario); err == nil {
		t.Fatal("negative expected detection offset was accepted")
	}
}

func TestDefenseValidationScenarioContractV02RequiresEnabledAcceptanceGates(t *testing.T) {
	tests := map[string]func(map[string]any){
		"missing_native_route": func(gates map[string]any) {
			delete(gates, "requires_native_authorization_route_reproduction")
		},
		"disabled_backend": func(gates map[string]any) {
			gates["requires_concrete_isolated_cosmos_evm_backend"] = false
		},
		"wrong_type": func(gates map[string]any) {
			gates["requires_independent_collector"] = "true"
		},
		"unrelated_placeholder": func(gates map[string]any) {
			for key := range gates {
				delete(gates, key)
			}
			gates["test"] = true
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			scenario := readDefenseValidationScenarioFixtureV02(t, "unauthorized-source-account-v1.json")
			mutate(scenario.AcceptanceGate)
			if err := ValidateDefenseValidationScenarioV02(scenario); err == nil {
				t.Fatal("weakened acceptance gate was accepted")
			}
		})
	}
}

func TestDefenseValidationScenarioContractV02RejectsUnsupportedControlClass(t *testing.T) {
	scenario := readDefenseValidationScenarioFixtureV02(t, "unauthorized-source-account-v1.json")
	scenario.ControlContract.ControlClass = "placeholder"
	scenario.ControlContract.CandidateControl = "placeholder"
	if err := ValidateDefenseValidationScenarioV02(scenario); err == nil {
		t.Fatal("unsupported control class bypassed mandatory acceptance gates")
	}
}

func TestDefenseValidationScenarioContractV02VerifiesMatchedFieldValues(t *testing.T) {
	tests := map[string]func(*DefenseValidationScenarioV02){
		"missing_value": func(scenario *DefenseValidationScenarioV02) {
			delete(scenario.Matrix.Cases[1].MatchedValues, "amount")
		},
		"different_value": func(scenario *DefenseValidationScenarioV02) {
			scenario.Matrix.Cases[1].MatchedValues["amount"] = 2
		},
		"contradictory_observation_window": func(scenario *DefenseValidationScenarioV02) {
			scenario.Matrix.Cases[1].MatchedValues["observation_window_ms"] = 2999
		},
		"undeclared_value": func(scenario *DefenseValidationScenarioV02) {
			scenario.Matrix.MatchedFields = append(scenario.Matrix.MatchedFields, "undeclared_pair_field")
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			scenario := readDefenseValidationScenarioFixtureV02(t, "unauthorized-source-account-v1.json")
			mutate(&scenario)
			if err := ValidateDefenseValidationScenarioV02(scenario); err == nil {
				t.Fatal("unproven matched-field claim was accepted")
			}
		})
	}
}

func TestDefenseValidationScenarioContractV02RejectsEvidentiaryStatus(t *testing.T) {
	for _, status := range []string{"validated", "executed", "active", "production"} {
		t.Run(status, func(t *testing.T) {
			scenario := readDefenseValidationScenarioFixtureV02(t, "unauthorized-source-account-v1.json")
			scenario.Status = status
			if err := ValidateDefenseValidationScenarioV02(scenario); err == nil {
				t.Fatalf("evidentiary scenario status %q was accepted", status)
			}
		})
	}
}

func TestDefenseValidationScenarioDigestV02BindsValidatedContent(t *testing.T) {
	data := readDefenseValidationScenarioFixtureBytesV02(t, "unauthorized-source-account-v1.json")
	scenario, err := ParseDefenseValidationScenarioV02(data)
	if err != nil {
		t.Fatal(err)
	}
	first, err := DefenseValidationScenarioDigestV02(scenario)
	if err != nil {
		t.Fatal(err)
	}
	mutatedData := bytes.Replace(data, []byte(`"delegation_present": false`), []byte(`"delegation_present": true`), 1)
	if bytes.Equal(mutatedData, data) {
		t.Fatal("security-critical fixture field was not found")
	}
	mutated, err := ParseDefenseValidationScenarioV02(mutatedData)
	if err != nil {
		t.Fatal(err)
	}
	second, err := DefenseValidationScenarioDigestV02(mutated)
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("unmodeled security-critical scenario content did not affect the scenario digest")
	}

	scenario.Matrix.Cases[0].Description += " Content-bound revision."
	if _, err := DefenseValidationScenarioDigestV02(scenario); err == nil {
		t.Fatal("in-memory mutation of a parsed complete contract did not fail closed")
	}
}

func TestDefenseValidationScenarioContractV02RejectsDuplicateJSONKeys(t *testing.T) {
	data := readDefenseValidationScenarioFixtureBytesV02(t, "unauthorized-source-account-v1.json")
	duplicate := bytes.Replace(data, []byte(`"status": "planned",`), []byte(`"status": "planned", "status": "draft",`), 1)
	if _, err := ParseDefenseValidationScenarioV02(duplicate); err == nil {
		t.Fatal("duplicate scenario JSON key was accepted")
	}
}

func readDefenseValidationScenarioFixtureV02(t *testing.T, name string) DefenseValidationScenarioV02 {
	t.Helper()
	data := readDefenseValidationScenarioFixtureBytesV02(t, name)
	scenario, err := ParseDefenseValidationScenarioV02(data)
	if err != nil {
		t.Fatalf("parse scenario: %v", err)
	}
	return scenario
}

func readDefenseValidationScenarioFixtureBytesV02(t *testing.T, name string) []byte {
	t.Helper()
	path := filepath.Join("..", "..", "..", "..", "docs", "defense-validation", "scenarios", name)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read scenario: %v", err)
	}
	return data
}
