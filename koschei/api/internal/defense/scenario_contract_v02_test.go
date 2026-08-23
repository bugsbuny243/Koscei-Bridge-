package defense

import (
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
		Contract: DefenseValidationScenarioContractV02,
		ScenarioRef: "scenario:test:unsafe",
		ScenarioVersion: "v1.0.0",
		Title: "unsafe",
		Status: "planned",
		Chain: "sandbox",
		RulesetVersion: DefenseValidationRulesetVersionV02,
		ClaimBoundary: DefenseValidationScenarioClaimBoundaryV02{ProductionClaimAllowed: true},
		Environment: DefenseValidationScenarioEnvironmentV02{ExecutionMode: "isolated_sandbox", OwnerApprovalRequired: true, DefaultOff: true},
		ControlContract: DefenseValidationScenarioControlContractV02{ControlClass: "test", CandidateControl: "test", IndependentCollectorRequired: true, AdapterVersionRequired: true, ConfigurationHashRequired: true, ProductionWiringRequiredForProductionClaim: true},
		Matrix: DefenseValidationScenarioMatrixV02{
			PairRef: "pair:test", MatchedFields: []string{"operation"}, SingleSecurityDifference: "authority",
			Cases: []DefenseValidationScenarioCaseV02{
				{CaseRef: "attack", CaseKind: DefenseValidationCaseAttackV02, Description: "attack", ImpactDeadlineMS: &deadline, ObservationWindowMS: 3000, ExpectedControlBehavior: DefenseValidationScenarioExpectedBehaviorV02{BlockOrAlertRequired: true, LatestDetectionOffsetMS: &deadline}},
				{CaseRef: "benign", CaseKind: DefenseValidationCaseBenignV02, Description: "benign", ObservationWindowMS: 3000, ExpectedControlBehavior: DefenseValidationScenarioExpectedBehaviorV02{FalsePositiveForbidden: true}},
			},
		},
		RequiredRunEvidence: []string{"runner_identity_hash", "pre_state_hash", "post_state_hash", "independent_observation_hash", "control_configuration_hash", "completed_observation_window"},
		AcceptanceGate: map[string]any{"test": true},
		Limitations: []string{"test"},
	}
	if err := ValidateDefenseValidationScenarioV02(scenario); err == nil {
		t.Fatal("unsafe production claim boundary accepted")
	}
}
