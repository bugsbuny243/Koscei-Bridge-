package defense

import (
	"encoding/json"
	"errors"
	"fmt"
	"strings"
)

const DefenseValidationScenarioContractV02 = "koschei-defense-validation-scenario/v0.2"

const (
	DefenseValidationScenarioExecutionForkV02    = "isolated_pinned_fork"
	DefenseValidationScenarioExecutionSandboxV02 = "isolated_sandbox"
)

var defenseValidationScenarioAcceptanceGatesV02 = map[string][]string{
	"": {
		"requires_non_test_runtime_caller_for_production_claim",
	},
	"pre_signing_execution_integrity": {
		"requires_concrete_isolated_evm_backend",
		"requires_no_bypass_signing_path",
	},
	"state_transition_authority_integrity": {
		"requires_machine_validated_scenario_contract",
		"requires_deterministic_authority_binding_adapter",
		"requires_authenticated_authority_evidence",
		"requires_execution_containment_receipt",
		"requires_concrete_isolated_cosmos_evm_backend",
		"requires_native_authorization_route_reproduction",
		"requires_independent_collector",
		"requires_no_unauthorized_state_mutation",
	},
}

var defenseValidationScenarioCandidateControlsV02 = map[string]string{
	"pre_signing_execution_integrity":      "koschei_execution_proof",
	"state_transition_authority_integrity": "koschei_execution_containment_authority_binding",
}

type DefenseValidationScenarioClaimBoundaryV02 struct {
	IsExecutionEvidence    bool `json:"is_execution_evidence"`
	IsValidationResult     bool `json:"is_validation_result"`
	ProductionClaimAllowed bool `json:"production_claim_allowed"`
	MainnetTransactionSent bool `json:"mainnet_transaction_sent"`
	VerdictAuthority       bool `json:"verdict_authority"`
}

type DefenseValidationScenarioEnvironmentV02 struct {
	ExecutionMode                string `json:"execution_mode"`
	ProductionIdentityUsed       bool   `json:"production_identity_used"`
	WalletCustody                bool   `json:"wallet_custody"`
	MainnetSubmissionAllowed     bool   `json:"mainnet_submission_allowed"`
	NetworkAccessDuringExecution bool   `json:"network_access_during_execution"`
	OwnerApprovalRequired        bool   `json:"owner_approval_required"`
	DefaultOff                   bool   `json:"default_off"`
}

type DefenseValidationScenarioControlContractV02 struct {
	ControlClass                               string `json:"control_class"`
	CandidateControl                           string `json:"candidate_control"`
	IndependentCollectorRequired               bool   `json:"independent_collector_required"`
	AdapterVersionRequired                     bool   `json:"adapter_version_required"`
	ConfigurationHashRequired                  bool   `json:"configuration_hash_required"`
	ProductionWiringRequiredForProductionClaim bool   `json:"production_wiring_required_for_production_claim"`
}

type DefenseValidationScenarioExpectedBehaviorV02 struct {
	BlockOrAlertRequired    bool     `json:"block_or_alert_required"`
	LatestDetectionOffsetMS *int64   `json:"latest_detection_offset_ms,omitempty"`
	FalsePositiveForbidden  bool     `json:"false_positive_forbidden,omitempty"`
	ExpectedReasons         []string `json:"expected_reasons,omitempty"`
}

type DefenseValidationScenarioCaseV02 struct {
	CaseRef                 string                                       `json:"case_ref"`
	CaseKind                string                                       `json:"case_kind"`
	Description             string                                       `json:"description"`
	ImpactDeadlineMS        *int64                                       `json:"impact_deadline_ms"`
	ObservationWindowMS     int64                                        `json:"observation_window_ms"`
	ExpectedControlBehavior DefenseValidationScenarioExpectedBehaviorV02 `json:"expected_control_behavior"`
}

type DefenseValidationScenarioMatrixV02 struct {
	PairRef                  string                             `json:"pair_ref"`
	MatchedFields            []string                           `json:"matched_fields"`
	SingleSecurityDifference string                             `json:"single_security_difference"`
	Cases                    []DefenseValidationScenarioCaseV02 `json:"cases"`
}

type DefenseValidationScenarioV02 struct {
	Contract            string                                      `json:"contract"`
	ScenarioRef         string                                      `json:"scenario_ref"`
	ScenarioVersion     string                                      `json:"scenario_version"`
	Title               string                                      `json:"title"`
	Status              string                                      `json:"status"`
	Chain               string                                      `json:"chain"`
	RulesetVersion      string                                      `json:"ruleset_version"`
	ClaimBoundary       DefenseValidationScenarioClaimBoundaryV02   `json:"claim_boundary"`
	Environment         DefenseValidationScenarioEnvironmentV02     `json:"environment"`
	ControlContract     DefenseValidationScenarioControlContractV02 `json:"control_contract"`
	Matrix              DefenseValidationScenarioMatrixV02          `json:"matrix"`
	RequiredRunEvidence []string                                    `json:"required_run_evidence"`
	AcceptanceGate      map[string]any                              `json:"acceptance_gate"`
	Limitations         []string                                    `json:"limitations"`
}

func ParseDefenseValidationScenarioV02(data []byte) (DefenseValidationScenarioV02, error) {
	var scenario DefenseValidationScenarioV02
	if err := json.Unmarshal(data, &scenario); err != nil {
		return DefenseValidationScenarioV02{}, fmt.Errorf("decode defense validation scenario: %w", err)
	}
	if err := ValidateDefenseValidationScenarioV02(scenario); err != nil {
		return DefenseValidationScenarioV02{}, err
	}
	return scenario, nil
}

func ValidateDefenseValidationScenarioV02(s DefenseValidationScenarioV02) error {
	if strings.TrimSpace(s.Contract) != DefenseValidationScenarioContractV02 {
		return fmt.Errorf("unsupported scenario contract %q", s.Contract)
	}
	if strings.TrimSpace(s.ScenarioRef) == "" || strings.TrimSpace(s.ScenarioVersion) == "" || strings.TrimSpace(s.Title) == "" || strings.TrimSpace(s.Chain) == "" {
		return errors.New("scenario identity is incomplete")
	}
	if strings.TrimSpace(s.RulesetVersion) != DefenseValidationRulesetVersionV02 {
		return fmt.Errorf("scenario ruleset must be %s", DefenseValidationRulesetVersionV02)
	}
	if strings.TrimSpace(s.Status) == "" {
		return errors.New("scenario status is required")
	}
	if s.ClaimBoundary.IsExecutionEvidence || s.ClaimBoundary.IsValidationResult || s.ClaimBoundary.ProductionClaimAllowed || s.ClaimBoundary.MainnetTransactionSent || s.ClaimBoundary.VerdictAuthority {
		return errors.New("scenario definition cannot claim execution, validation, production authority or mainnet submission")
	}
	if s.Environment.ProductionIdentityUsed || s.Environment.WalletCustody || s.Environment.MainnetSubmissionAllowed {
		return errors.New("scenario environment cannot use production identity, custody or mainnet submission")
	}
	executionMode := strings.ToLower(strings.TrimSpace(s.Environment.ExecutionMode))
	if !validDefenseValidationScenarioExecutionModeV02(executionMode) || !s.Environment.OwnerApprovalRequired || !s.Environment.DefaultOff {
		return errors.New("scenario environment must be explicit, owner-approved and default-off")
	}
	controlClass := strings.TrimSpace(s.ControlContract.ControlClass)
	candidateControl := strings.TrimSpace(s.ControlContract.CandidateControl)
	expectedCandidate, supportedControlClass := defenseValidationScenarioCandidateControlsV02[controlClass]
	if controlClass == "" || candidateControl == "" || !supportedControlClass || candidateControl != expectedCandidate {
		return errors.New("scenario control contract is incomplete")
	}
	if !s.ControlContract.IndependentCollectorRequired || !s.ControlContract.AdapterVersionRequired || !s.ControlContract.ConfigurationHashRequired || !s.ControlContract.ProductionWiringRequiredForProductionClaim {
		return errors.New("scenario control contract must preserve independent evidence and production-wiring gates")
	}
	if strings.TrimSpace(s.Matrix.PairRef) == "" || len(s.Matrix.MatchedFields) == 0 || strings.TrimSpace(s.Matrix.SingleSecurityDifference) == "" {
		return errors.New("scenario attack/benign pair contract is incomplete")
	}
	if err := validateDefenseValidationScenarioCasesV02(s.Matrix.Cases); err != nil {
		return err
	}
	for _, required := range []string{"runner_identity_hash", "pre_state_hash", "post_state_hash", "independent_observation_hash", "control_configuration_hash", "completed_observation_window"} {
		if !containsDefenseValidationScenarioStringV02(s.RequiredRunEvidence, required) {
			return fmt.Errorf("scenario required_run_evidence missing %q", required)
		}
	}
	if err := validateDefenseValidationScenarioAcceptanceGateV02(controlClass, s.AcceptanceGate); err != nil {
		return err
	}
	if len(s.Limitations) == 0 {
		return errors.New("scenario limitations are required")
	}
	return nil
}

func validateDefenseValidationScenarioCasesV02(cases []DefenseValidationScenarioCaseV02) error {
	if len(cases) < 2 {
		return errors.New("scenario must include matched attack and benign cases")
	}
	seen := map[string]bool{}
	attackCount, benignCount := 0, 0
	for _, c := range cases {
		ref := strings.TrimSpace(c.CaseRef)
		if ref == "" || seen[ref] {
			return errors.New("scenario case refs must be unique and non-empty")
		}
		seen[ref] = true
		if strings.TrimSpace(c.Description) == "" || c.ObservationWindowMS <= 0 {
			return fmt.Errorf("scenario case %q is incomplete", ref)
		}
		switch c.CaseKind {
		case DefenseValidationCaseAttackV02:
			attackCount++
			if c.ImpactDeadlineMS == nil || *c.ImpactDeadlineMS < 0 || *c.ImpactDeadlineMS > c.ObservationWindowMS {
				return fmt.Errorf("attack case %q has invalid impact deadline", ref)
			}
			if !c.ExpectedControlBehavior.BlockOrAlertRequired || c.ExpectedControlBehavior.LatestDetectionOffsetMS == nil || *c.ExpectedControlBehavior.LatestDetectionOffsetMS < 0 || *c.ExpectedControlBehavior.LatestDetectionOffsetMS > c.ObservationWindowMS || *c.ExpectedControlBehavior.LatestDetectionOffsetMS > *c.ImpactDeadlineMS {
				return fmt.Errorf("attack case %q does not require timely control behavior", ref)
			}
		case DefenseValidationCaseBenignV02:
			benignCount++
			if c.ImpactDeadlineMS != nil || c.ExpectedControlBehavior.BlockOrAlertRequired || !c.ExpectedControlBehavior.FalsePositiveForbidden {
				return fmt.Errorf("benign case %q has unsafe expected-control semantics", ref)
			}
		default:
			return fmt.Errorf("scenario case %q has unsupported kind %q", ref, c.CaseKind)
		}
	}
	if attackCount == 0 || benignCount == 0 {
		return errors.New("scenario must include at least one attack and one benign case")
	}
	return nil
}

func validDefenseValidationScenarioExecutionModeV02(value string) bool {
	switch value {
	case DefenseValidationExecutionForkV02, DefenseValidationExecutionSandboxV02, DefenseValidationScenarioExecutionForkV02, DefenseValidationScenarioExecutionSandboxV02:
		return true
	default:
		return false
	}
}

func validateDefenseValidationScenarioAcceptanceGateV02(controlClass string, gates map[string]any) error {
	if len(gates) == 0 {
		return errors.New("scenario acceptance gate is required")
	}
	for key, value := range gates {
		if !strings.HasPrefix(strings.TrimSpace(key), "requires_") {
			continue
		}
		enabled, ok := value.(bool)
		if !ok || !enabled {
			return fmt.Errorf("scenario acceptance gate %q must be boolean true", key)
		}
	}
	controlRequired, ok := defenseValidationScenarioAcceptanceGatesV02[controlClass]
	if !ok {
		return fmt.Errorf("scenario acceptance gate has unsupported control class %q", controlClass)
	}
	required := append([]string(nil), defenseValidationScenarioAcceptanceGatesV02[""]...)
	required = append(required, controlRequired...)
	for _, key := range required {
		enabled, ok := gates[key].(bool)
		if !ok || !enabled {
			return fmt.Errorf("scenario acceptance gate missing enabled %q", key)
		}
	}
	return nil
}

func containsDefenseValidationScenarioStringV02(values []string, wanted string) bool {
	wanted = strings.TrimSpace(wanted)
	for _, value := range values {
		if strings.TrimSpace(value) == wanted {
			return true
		}
	}
	return false
}
