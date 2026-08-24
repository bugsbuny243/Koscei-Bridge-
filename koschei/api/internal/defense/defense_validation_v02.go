package defense

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const DefenseValidationRulesetVersionV02 = "koschei-defense-validation-rules-v0.2.0"

const (
	DefenseValidationCaseAttackV02 = "attack"
	DefenseValidationCaseBenignV02 = "benign"

	DefenseValidationExecutionForkV02    = "fork"
	DefenseValidationExecutionSandboxV02 = "sandbox"

	DefenseValidationEvidenceVerifiedV02   = "verified"
	DefenseValidationEvidenceObservedV02   = "observed"
	DefenseValidationEvidenceUnverifiedV02 = "unverified"

	DefenseValidationObservationAlertedV02 = "alerted"
	DefenseValidationObservationNoAlertV02 = "no_alert"

	DefenseValidationOutcomeCaughtInTimeV02  = "caught_in_time"
	DefenseValidationOutcomeCaughtLateV02    = "caught_late"
	DefenseValidationOutcomeMissedV02        = "missed"
	DefenseValidationOutcomeFalsePositiveV02 = "false_positive"
	DefenseValidationOutcomeCleanV02         = "clean"
	DefenseValidationOutcomeIncompleteV02    = "incomplete"

	DefenseValidationVerdictValidatedV02  = "validated"
	DefenseValidationVerdictFailedV02     = "failed"
	DefenseValidationVerdictIncompleteV02 = "incomplete"

	defenseValidationRuleVerifiedExecutionV02 = "DV-R01"
	defenseValidationRuleIndependentAlertV02  = "DV-R02"
	defenseValidationRuleDetectionDeadlineV02 = "DV-R03"
	defenseValidationRuleMissedAttackV02      = "DV-R04"
	defenseValidationRuleBenignControlV02     = "DV-R05"
	defenseValidationRuleCompleteMatrixV02    = "DV-R06"
)

type DefenseValidationControlV02 struct {
	ControlRef         string `json:"control_ref"`
	AdapterVersion     string `json:"adapter_version"`
	ConfigurationHash  string `json:"configuration_hash"`
	CollectorRef       string `json:"collector_ref"`
	CollectorPublicKey string `json:"collector_public_key"`
}

type DefenseValidationCaseV02 struct {
	CaseRef                  string `json:"case_ref"`
	CaseKind                 string `json:"case_kind"`
	TechniqueID              string `json:"technique_id"`
	ControlRef               string `json:"control_ref"`
	ControlConfigurationHash string `json:"control_configuration_hash"`
	ScenarioRef              string `json:"scenario_ref"`
	ScenarioVersion          string `json:"scenario_version"`
	ScenarioContractHash     string `json:"scenario_contract_hash"`
	Chain                    string `json:"chain,omitempty"`
	ChainID                  uint64 `json:"chain_id,omitempty"`
	ExecutionMode            string `json:"execution_mode"`
	ExecutionRef             string `json:"execution_ref"`
	ExecutionHash            string `json:"execution_hash"`
	PreStateHash             string `json:"pre_state_hash"`
	PostStateHash            string `json:"post_state_hash"`
	EvidenceState            string `json:"evidence_state"`
	ImpactOffsetMS           *int64 `json:"impact_offset_ms,omitempty"`
	DetectionDeadlineMS      *int64 `json:"detection_deadline_ms,omitempty"`
	ObservationWindowMS      int64  `json:"observation_window_ms"`
	MainnetTransactionSent   bool   `json:"mainnet_transaction_sent"`
}

type DefenseValidationObservationV02 struct {
	ControlRef                   string `json:"control_ref"`
	CollectorRef                 string `json:"collector_ref"`
	CaseRef                      string `json:"case_ref"`
	Status                       string `json:"status"`
	ObservationEvidenceRef       string `json:"observation_evidence_ref"`
	ObservationEvidenceHash      string `json:"observation_evidence_hash"`
	AlertObservedOffsetMS        *int64 `json:"alert_observed_offset_ms,omitempty"`
	AlertEvidenceRef             string `json:"alert_evidence_ref,omitempty"`
	AlertEvidenceHash            string `json:"alert_evidence_hash,omitempty"`
	ObservationCompletedOffsetMS int64  `json:"observation_completed_offset_ms"`
	EvidenceState                string `json:"evidence_state"`
}

type DefenseValidationInputV02 struct {
	RunRef               string                            `json:"run_ref"`
	Scenario             DefenseValidationScenarioV02      `json:"scenario"`
	ScenarioRef          string                            `json:"scenario_ref"`
	ScenarioVersion      string                            `json:"scenario_version"`
	ScenarioContractHash string                            `json:"scenario_contract_hash"`
	Chain                string                            `json:"chain"`
	ChainID              uint64                            `json:"chain_id,omitempty"`
	RulesetVersion       string                            `json:"ruleset_version"`
	Controls             []DefenseValidationControlV02     `json:"controls"`
	Cases                []DefenseValidationCaseV02        `json:"cases"`
	Observations         []DefenseValidationObservationV02 `json:"observations"`
}

type DefenseValidationCaseResultV02 struct {
	ControlRef               string   `json:"control_ref"`
	CaseRef                  string   `json:"case_ref"`
	CaseKind                 string   `json:"case_kind"`
	TechniqueID              string   `json:"technique_id"`
	ExecutionMode            string   `json:"execution_mode"`
	ExecutionEvidenceState   string   `json:"execution_evidence_state"`
	ImpactOffsetMS           *int64   `json:"impact_offset_ms,omitempty"`
	DetectionDeadlineMS      *int64   `json:"detection_deadline_ms,omitempty"`
	ObservationWindowMS      int64    `json:"observation_window_ms"`
	ObservationStatus        string   `json:"observation_status"`
	ObservationEvidenceState string   `json:"observation_evidence_state"`
	Outcome                  string   `json:"outcome"`
	DetectionMS              *int64   `json:"detection_ms,omitempty"`
	LeadTimeMS               *int64   `json:"lead_time_ms,omitempty"`
	TriggeredRules           []string `json:"triggered_rules"`
	EvidenceRefs             []string `json:"evidence_refs"`
	EvidenceHashes           []string `json:"evidence_hashes"`
	Limitations              []string `json:"limitations"`
}

type DefenseValidationCountsV02 struct {
	AttackCases    int `json:"attack_cases"`
	BenignCases    int `json:"benign_cases"`
	CaughtInTime   int `json:"caught_in_time"`
	CaughtLate     int `json:"caught_late"`
	Missed         int `json:"missed"`
	FalsePositives int `json:"false_positives"`
	Clean          int `json:"clean"`
	Incomplete     int `json:"incomplete"`
}

type DefenseValidationControlResultV02 struct {
	ControlRef         string                           `json:"control_ref"`
	AdapterVersion     string                           `json:"adapter_version"`
	ConfigurationHash  string                           `json:"configuration_hash"`
	CollectorRef       string                           `json:"collector_ref"`
	CollectorPublicKey string                           `json:"collector_public_key"`
	Verdict            string                           `json:"verdict"`
	TriggeredRules     []string                         `json:"triggered_rules"`
	Counts             DefenseValidationCountsV02       `json:"counts"`
	Cases              []DefenseValidationCaseResultV02 `json:"cases"`
}

type DefenseValidationReportV02 struct {
	RunRef                 string                              `json:"run_ref"`
	ScenarioRef            string                              `json:"scenario_ref"`
	ScenarioVersion        string                              `json:"scenario_version"`
	ScenarioContractHash   string                              `json:"scenario_contract_hash"`
	Chain                  string                              `json:"chain"`
	ChainID                uint64                              `json:"chain_id,omitempty"`
	RulesetVersion         string                              `json:"ruleset_version"`
	Verdict                string                              `json:"verdict"`
	Controls               []DefenseValidationControlResultV02 `json:"controls"`
	ReportHash             string                              `json:"report_hash"`
	MainnetTransactionSent bool                                `json:"mainnet_transaction_sent"`
	VerdictAuthority       bool                                `json:"verdict_authority"`
}

// EvaluateDefenseValidationV02 is deterministic and I/O-free. It starts no
// process, calls no model, mutates no control and cannot submit transactions.
func EvaluateDefenseValidationV02(input DefenseValidationInputV02) (DefenseValidationReportV02, error) {
	input = normalizeDefenseValidationInputV02(input)
	if err := validateDefenseValidationInputV02(input); err != nil {
		return DefenseValidationReportV02{}, err
	}

	cases := make(map[string]DefenseValidationCaseV02, len(input.Cases))
	for _, item := range input.Cases {
		cases[defenseValidationObservationKeyV02(item.ControlRef, item.CaseRef)] = item
	}
	controls := make(map[string]DefenseValidationControlV02, len(input.Controls))
	for _, item := range input.Controls {
		controls[item.ControlRef] = item
	}
	observations := make(map[string]DefenseValidationObservationV02, len(input.Observations))
	for _, item := range input.Observations {
		control, ok := controls[item.ControlRef]
		if !ok {
			return DefenseValidationReportV02{}, fmt.Errorf("observation references unknown control %q", item.ControlRef)
		}
		validationCase, ok := cases[defenseValidationObservationKeyV02(item.ControlRef, item.CaseRef)]
		if !ok {
			return DefenseValidationReportV02{}, fmt.Errorf("observation references unknown control/case pair %q/%q", item.ControlRef, item.CaseRef)
		}
		if item.CollectorRef != control.CollectorRef {
			return DefenseValidationReportV02{}, fmt.Errorf("observation collector does not match control %q", item.ControlRef)
		}
		if validationCase.ControlRef != control.ControlRef {
			return DefenseValidationReportV02{}, fmt.Errorf("observation control does not match case %q binding", item.CaseRef)
		}
		if item.AlertObservedOffsetMS != nil && *item.AlertObservedOffsetMS > validationCase.ObservationWindowMS {
			return DefenseValidationReportV02{}, fmt.Errorf("observation alert for case %q falls outside the declared window", item.CaseRef)
		}
		key := defenseValidationObservationKeyV02(item.ControlRef, item.CaseRef)
		if _, exists := observations[key]; exists {
			return DefenseValidationReportV02{}, fmt.Errorf("duplicate observation for control %q and case %q", item.ControlRef, item.CaseRef)
		}
		observations[key] = item
	}

	report := DefenseValidationReportV02{
		RunRef:                 input.RunRef,
		ScenarioRef:            input.ScenarioRef,
		ScenarioVersion:        input.ScenarioVersion,
		ScenarioContractHash:   input.ScenarioContractHash,
		Chain:                  input.Chain,
		ChainID:                input.ChainID,
		RulesetVersion:         input.RulesetVersion,
		Verdict:                DefenseValidationVerdictValidatedV02,
		MainnetTransactionSent: false,
		VerdictAuthority:       false,
	}
	for _, control := range input.Controls {
		result := evaluateDefenseValidationControlV02(control, input.Cases, input.Scenario.Matrix.Cases, observations)
		report.Controls = append(report.Controls, result)
		if result.Verdict == DefenseValidationVerdictFailedV02 {
			report.Verdict = DefenseValidationVerdictFailedV02
		} else if result.Verdict == DefenseValidationVerdictIncompleteV02 && report.Verdict != DefenseValidationVerdictFailedV02 {
			report.Verdict = DefenseValidationVerdictIncompleteV02
		}
	}
	report.ReportHash = defenseValidationReportHashV02(report)
	return report, nil
}

func evaluateDefenseValidationControlV02(control DefenseValidationControlV02, cases []DefenseValidationCaseV02, expectedCases []DefenseValidationScenarioCaseV02, observations map[string]DefenseValidationObservationV02) DefenseValidationControlResultV02 {
	result := DefenseValidationControlResultV02{
		ControlRef:         control.ControlRef,
		AdapterVersion:     control.AdapterVersion,
		ConfigurationHash:  control.ConfigurationHash,
		CollectorRef:       control.CollectorRef,
		CollectorPublicKey: control.CollectorPublicKey,
		Verdict:            DefenseValidationVerdictValidatedV02,
	}
	seenCases := make(map[string]struct{}, len(expectedCases))
	for _, validationCase := range cases {
		if validationCase.ControlRef != control.ControlRef {
			continue
		}
		seenCases[validationCase.CaseRef] = struct{}{}
		if validationCase.CaseKind == DefenseValidationCaseAttackV02 {
			result.Counts.AttackCases++
		} else {
			result.Counts.BenignCases++
		}
		observation, ok := observations[defenseValidationObservationKeyV02(control.ControlRef, validationCase.CaseRef)]
		caseResult := evaluateDefenseValidationCaseV02(control, validationCase, observation, ok)
		result.Cases = append(result.Cases, caseResult)
		result.TriggeredRules = append(result.TriggeredRules, caseResult.TriggeredRules...)
		switch caseResult.Outcome {
		case DefenseValidationOutcomeCaughtInTimeV02:
			result.Counts.CaughtInTime++
		case DefenseValidationOutcomeCleanV02:
			result.Counts.Clean++
		case DefenseValidationOutcomeCaughtLateV02:
			result.Counts.CaughtLate++
			result.Verdict = DefenseValidationVerdictFailedV02
		case DefenseValidationOutcomeMissedV02:
			result.Counts.Missed++
			result.Verdict = DefenseValidationVerdictFailedV02
		case DefenseValidationOutcomeFalsePositiveV02:
			result.Counts.FalsePositives++
			result.Verdict = DefenseValidationVerdictFailedV02
		default:
			result.Counts.Incomplete++
			if result.Verdict != DefenseValidationVerdictFailedV02 {
				result.Verdict = DefenseValidationVerdictIncompleteV02
			}
		}
	}
	for _, expected := range expectedCases {
		if _, ok := seenCases[strings.TrimSpace(expected.CaseRef)]; ok {
			continue
		}
		if expected.CaseKind == DefenseValidationCaseAttackV02 {
			result.Counts.AttackCases++
		} else {
			result.Counts.BenignCases++
		}
		result.Counts.Incomplete++
		result.Cases = append(result.Cases, missingDefenseValidationCaseV02(control, expected))
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleCompleteMatrixV02)
		if result.Verdict != DefenseValidationVerdictFailedV02 {
			result.Verdict = DefenseValidationVerdictIncompleteV02
		}
	}
	if result.Counts.AttackCases == 0 || result.Counts.BenignCases == 0 {
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleCompleteMatrixV02)
		if result.Verdict != DefenseValidationVerdictFailedV02 {
			result.Verdict = DefenseValidationVerdictIncompleteV02
		}
	}
	sort.Slice(result.Cases, func(i, j int) bool { return result.Cases[i].CaseRef < result.Cases[j].CaseRef })
	result.TriggeredRules = sortedUniqueDefenseValidationStringsV02(result.TriggeredRules)
	return result
}

func missingDefenseValidationCaseV02(control DefenseValidationControlV02, expected DefenseValidationScenarioCaseV02) DefenseValidationCaseResultV02 {
	return DefenseValidationCaseResultV02{
		ControlRef:             control.ControlRef,
		CaseRef:                strings.TrimSpace(expected.CaseRef),
		CaseKind:               strings.TrimSpace(expected.CaseKind),
		ExecutionEvidenceState: DefenseValidationEvidenceUnverifiedV02,
		ImpactOffsetMS:         cloneDefenseValidationInt64V02(expected.ImpactDeadlineMS),
		DetectionDeadlineMS:    cloneDefenseValidationInt64V02(expected.ExpectedControlBehavior.LatestDetectionOffsetMS),
		ObservationWindowMS:    expected.ObservationWindowMS,
		Outcome:                DefenseValidationOutcomeIncompleteV02,
		TriggeredRules:         []string{defenseValidationRuleCompleteMatrixV02},
		Limitations:            []string{"scenario case execution is missing"},
	}
}

func evaluateDefenseValidationCaseV02(control DefenseValidationControlV02, validationCase DefenseValidationCaseV02, observation DefenseValidationObservationV02, exists bool) DefenseValidationCaseResultV02 {
	result := DefenseValidationCaseResultV02{
		ControlRef:             control.ControlRef,
		CaseRef:                validationCase.CaseRef,
		CaseKind:               validationCase.CaseKind,
		TechniqueID:            validationCase.TechniqueID,
		ExecutionMode:          validationCase.ExecutionMode,
		ExecutionEvidenceState: validationCase.EvidenceState,
		ImpactOffsetMS:         cloneDefenseValidationInt64V02(validationCase.ImpactOffsetMS),
		DetectionDeadlineMS:    cloneDefenseValidationInt64V02(validationCase.DetectionDeadlineMS),
		ObservationWindowMS:    validationCase.ObservationWindowMS,
		Outcome:                DefenseValidationOutcomeIncompleteV02,
	}
	if validationCase.EvidenceState != DefenseValidationEvidenceVerifiedV02 {
		return incompleteDefenseValidationCaseV02(result, defenseValidationRuleVerifiedExecutionV02, "case execution evidence is not verified")
	}
	result.EvidenceRefs = append(result.EvidenceRefs, validationCase.ExecutionRef)
	result.EvidenceHashes = append(result.EvidenceHashes, validationCase.ExecutionHash, validationCase.PreStateHash, validationCase.PostStateHash)
	if !exists {
		return incompleteDefenseValidationCaseV02(result, defenseValidationRuleCompleteMatrixV02, "independent control observation is missing")
	}
	result.ObservationStatus = observation.Status
	result.ObservationEvidenceState = observation.EvidenceState
	if observation.EvidenceState != DefenseValidationEvidenceVerifiedV02 {
		return incompleteDefenseValidationCaseV02(result, defenseValidationRuleIndependentAlertV02, "control observation evidence is not verified")
	}
	result.EvidenceRefs = append(result.EvidenceRefs, observation.ObservationEvidenceRef)
	result.EvidenceHashes = append(result.EvidenceHashes, observation.ObservationEvidenceHash)
	if observation.ObservationCompletedOffsetMS < validationCase.ObservationWindowMS {
		return incompleteDefenseValidationCaseV02(result, defenseValidationRuleCompleteMatrixV02, "observation window did not complete")
	}
	if observation.AlertEvidenceRef != "" {
		result.EvidenceRefs = append(result.EvidenceRefs, observation.AlertEvidenceRef)
		result.EvidenceHashes = append(result.EvidenceHashes, observation.AlertEvidenceHash)
	}

	if validationCase.CaseKind == DefenseValidationCaseBenignV02 {
		if observation.Status == DefenseValidationObservationAlertedV02 {
			result.Outcome = DefenseValidationOutcomeFalsePositiveV02
			result.DetectionMS = cloneDefenseValidationInt64V02(observation.AlertObservedOffsetMS)
			result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleBenignControlV02)
		} else {
			result.Outcome = DefenseValidationOutcomeCleanV02
		}
		return finalizeDefenseValidationCaseV02(result)
	}
	if observation.Status == DefenseValidationObservationNoAlertV02 {
		result.Outcome = DefenseValidationOutcomeMissedV02
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleMissedAttackV02)
		return finalizeDefenseValidationCaseV02(result)
	}

	result.DetectionMS = cloneDefenseValidationInt64V02(observation.AlertObservedOffsetMS)
	leadTime := *validationCase.DetectionDeadlineMS - *observation.AlertObservedOffsetMS
	result.LeadTimeMS = &leadTime
	if leadTime >= 0 {
		result.Outcome = DefenseValidationOutcomeCaughtInTimeV02
	} else {
		result.Outcome = DefenseValidationOutcomeCaughtLateV02
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleDetectionDeadlineV02)
	}
	return finalizeDefenseValidationCaseV02(result)
}

func incompleteDefenseValidationCaseV02(result DefenseValidationCaseResultV02, rule, limitation string) DefenseValidationCaseResultV02 {
	result.TriggeredRules = append(result.TriggeredRules, rule)
	result.Limitations = append(result.Limitations, limitation)
	return finalizeDefenseValidationCaseV02(result)
}

func finalizeDefenseValidationCaseV02(result DefenseValidationCaseResultV02) DefenseValidationCaseResultV02 {
	result.TriggeredRules = sortedUniqueDefenseValidationStringsV02(result.TriggeredRules)
	result.EvidenceRefs = sortedUniqueDefenseValidationStringsV02(result.EvidenceRefs)
	result.EvidenceHashes = sortedUniqueDefenseValidationStringsV02(result.EvidenceHashes)
	return result
}

func validateDefenseValidationInputV02(input DefenseValidationInputV02) error {
	if input.RunRef == "" || input.ScenarioRef == "" || input.ScenarioVersion == "" || input.Chain == "" {
		return errors.New("run, scenario, scenario version and chain are required")
	}
	if input.RulesetVersion != DefenseValidationRulesetVersionV02 {
		return fmt.Errorf("unsupported defense validation ruleset %q", input.RulesetVersion)
	}
	if !validDefenseValidationHashV02(input.ScenarioContractHash) {
		return errors.New("scenario contract hash is invalid")
	}
	if !defenseValidationScenarioHasCompleteContractV02(input.Scenario) {
		return errors.New("complete parsed scenario contract is required")
	}
	scenarioDigest, err := DefenseValidationScenarioDigestV02(input.Scenario)
	if err != nil {
		return fmt.Errorf("validate report scenario contract: %w", err)
	}
	if input.ScenarioRef != strings.TrimSpace(input.Scenario.ScenarioRef) || input.ScenarioVersion != strings.TrimSpace(input.Scenario.ScenarioVersion) || input.Chain != strings.ToLower(strings.TrimSpace(input.Scenario.Chain)) || input.RulesetVersion != strings.TrimSpace(input.Scenario.RulesetVersion) || !strings.EqualFold(input.ScenarioContractHash, scenarioDigest) {
		return errors.New("report scenario identity does not match the complete scenario contract")
	}
	if len(input.Controls) == 0 {
		return errors.New("at least one control is required")
	}
	expectedCases := make(map[string]DefenseValidationScenarioCaseV02, len(input.Scenario.Matrix.Cases))
	for _, expected := range input.Scenario.Matrix.Cases {
		expectedCases[strings.TrimSpace(expected.CaseRef)] = expected
	}
	seenControls := map[string]DefenseValidationControlV02{}
	for _, control := range input.Controls {
		if control.ControlRef == "" || control.AdapterVersion == "" || control.CollectorRef == "" || !validDefenseValidationHashV02(control.ConfigurationHash) {
			return fmt.Errorf("control %q has incomplete identity evidence", control.ControlRef)
		}
		if _, err := requireDefenseValidationCollectorPublicKeyV02(control.CollectorPublicKey); err != nil {
			return fmt.Errorf("control %q collector trust: %w", control.ControlRef, err)
		}
		if control.ControlRef == control.CollectorRef {
			return fmt.Errorf("control %q cannot be its own independent collector", control.ControlRef)
		}
		if _, ok := seenControls[control.ControlRef]; ok {
			return fmt.Errorf("duplicate control %q", control.ControlRef)
		}
		seenControls[control.ControlRef] = control
	}
	seenCases := map[string]struct{}{}
	for _, item := range input.Cases {
		if item.CaseRef == "" || item.TechniqueID == "" || item.ExecutionRef == "" {
			return fmt.Errorf("case %q has incomplete identity evidence", item.CaseRef)
		}
		caseKey := defenseValidationObservationKeyV02(item.ControlRef, item.CaseRef)
		if _, ok := seenCases[caseKey]; ok {
			return fmt.Errorf("duplicate case %q for control %q", item.CaseRef, item.ControlRef)
		}
		seenCases[caseKey] = struct{}{}
		if item.CaseKind != DefenseValidationCaseAttackV02 && item.CaseKind != DefenseValidationCaseBenignV02 {
			return fmt.Errorf("case %q has unsupported kind %q", item.CaseRef, item.CaseKind)
		}
		expected, ok := expectedCases[item.CaseRef]
		if !ok {
			return fmt.Errorf("case %q is not declared by the complete scenario contract", item.CaseRef)
		}
		if item.CaseKind != strings.TrimSpace(expected.CaseKind) || item.ObservationWindowMS != expected.ObservationWindowMS || !equalDefenseValidationInt64PointersV02(item.ImpactOffsetMS, expected.ImpactDeadlineMS) || !equalDefenseValidationInt64PointersV02(item.DetectionDeadlineMS, expected.ExpectedControlBehavior.LatestDetectionOffsetMS) {
			return fmt.Errorf("case %q execution timing or kind does not match scenario contract", item.CaseRef)
		}
		control, ok := seenControls[item.ControlRef]
		if !ok || !validDefenseValidationHashV02(item.ControlConfigurationHash) || !strings.EqualFold(item.ControlConfigurationHash, control.ConfigurationHash) {
			return fmt.Errorf("case %q control configuration does not match report control", item.CaseRef)
		}
		if item.ScenarioRef != input.ScenarioRef || item.ScenarioVersion != input.ScenarioVersion || !validDefenseValidationHashV02(item.ScenarioContractHash) || !strings.EqualFold(item.ScenarioContractHash, input.ScenarioContractHash) {
			return fmt.Errorf("case %q scenario contract does not match report scenario", item.CaseRef)
		}
		if (item.Chain == "") != (item.ChainID == 0) {
			return fmt.Errorf("case %q has incomplete execution chain identity", item.CaseRef)
		}
		if item.Chain != "" && (item.Chain != input.Chain || item.ChainID != input.ChainID) {
			return fmt.Errorf("case %q execution chain does not match report scenario", item.CaseRef)
		}
		if item.ExecutionMode != DefenseValidationExecutionForkV02 && item.ExecutionMode != DefenseValidationExecutionSandboxV02 {
			return fmt.Errorf("case %q must execute in a fork or sandbox", item.CaseRef)
		}
		if !defenseValidationScenarioExecutionModeMatchesV02(input.Scenario.Environment.ExecutionMode, item.ExecutionMode) {
			return fmt.Errorf("case %q execution mode does not match scenario environment", item.CaseRef)
		}
		if !validDefenseValidationEvidenceStateV02(item.EvidenceState) {
			return fmt.Errorf("case %q has unsupported evidence state %q", item.CaseRef, item.EvidenceState)
		}
		if !validDefenseValidationHashV02(item.ExecutionHash) || !validDefenseValidationHashV02(item.PreStateHash) || !validDefenseValidationHashV02(item.PostStateHash) {
			return fmt.Errorf("case %q has invalid execution/state hashes", item.CaseRef)
		}
		if item.ObservationWindowMS <= 0 {
			return fmt.Errorf("case %q has invalid observation window", item.CaseRef)
		}
		if item.MainnetTransactionSent {
			return fmt.Errorf("case %q crossed the no-mainnet boundary", item.CaseRef)
		}
		if item.CaseKind == DefenseValidationCaseAttackV02 {
			if item.ImpactOffsetMS == nil || *item.ImpactOffsetMS < 0 || *item.ImpactOffsetMS > item.ObservationWindowMS {
				return fmt.Errorf("attack case %q has invalid impact deadline", item.CaseRef)
			}
			if item.DetectionDeadlineMS == nil || *item.DetectionDeadlineMS < 0 || *item.DetectionDeadlineMS > *item.ImpactOffsetMS || *item.DetectionDeadlineMS > item.ObservationWindowMS {
				return fmt.Errorf("attack case %q has invalid detection deadline", item.CaseRef)
			}
		} else if item.ImpactOffsetMS != nil || item.DetectionDeadlineMS != nil {
			return fmt.Errorf("benign case %q cannot define impact or detection deadlines", item.CaseRef)
		}
	}
	for _, item := range input.Observations {
		if item.ControlRef == "" || item.CollectorRef == "" || item.CaseRef == "" || item.ObservationEvidenceRef == "" || !validDefenseValidationHashV02(item.ObservationEvidenceHash) || !validDefenseValidationEvidenceStateV02(item.EvidenceState) {
			return errors.New("observation has incomplete identity or evidence state")
		}
		if item.Status != DefenseValidationObservationAlertedV02 && item.Status != DefenseValidationObservationNoAlertV02 {
			return fmt.Errorf("observation for case %q has unsupported status %q", item.CaseRef, item.Status)
		}
		if item.ObservationCompletedOffsetMS < 0 {
			return fmt.Errorf("observation for case %q has invalid completion offset", item.CaseRef)
		}
		if item.Status == DefenseValidationObservationAlertedV02 {
			if item.AlertObservedOffsetMS == nil || *item.AlertObservedOffsetMS < 0 || *item.AlertObservedOffsetMS > item.ObservationCompletedOffsetMS || item.AlertEvidenceRef == "" || !validDefenseValidationHashV02(item.AlertEvidenceHash) {
				return fmt.Errorf("alert observation for case %q has incomplete alert evidence", item.CaseRef)
			}
		} else if item.AlertObservedOffsetMS != nil || item.AlertEvidenceRef != "" || item.AlertEvidenceHash != "" {
			return fmt.Errorf("no-alert observation for case %q contains alert evidence", item.CaseRef)
		}
	}
	return nil
}

func equalDefenseValidationInt64PointersV02(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func defenseValidationScenarioExecutionModeMatchesV02(scenarioMode, executionMode string) bool {
	scenarioMode = strings.ToLower(strings.TrimSpace(scenarioMode))
	executionMode = strings.ToLower(strings.TrimSpace(executionMode))
	switch executionMode {
	case DefenseValidationExecutionForkV02:
		return scenarioMode == DefenseValidationExecutionForkV02 || scenarioMode == DefenseValidationScenarioExecutionForkV02
	case DefenseValidationExecutionSandboxV02:
		return scenarioMode == DefenseValidationExecutionSandboxV02 || scenarioMode == DefenseValidationScenarioExecutionSandboxV02
	default:
		return false
	}
}

func normalizeDefenseValidationInputV02(input DefenseValidationInputV02) DefenseValidationInputV02 {
	input.RunRef = strings.TrimSpace(input.RunRef)
	input.ScenarioRef = strings.TrimSpace(input.ScenarioRef)
	input.ScenarioVersion = strings.TrimSpace(input.ScenarioVersion)
	input.ScenarioContractHash = strings.ToLower(strings.TrimSpace(input.ScenarioContractHash))
	input.Chain = strings.ToLower(strings.TrimSpace(input.Chain))
	input.RulesetVersion = strings.TrimSpace(input.RulesetVersion)
	input.Controls = append([]DefenseValidationControlV02(nil), input.Controls...)
	input.Cases = append([]DefenseValidationCaseV02(nil), input.Cases...)
	input.Observations = append([]DefenseValidationObservationV02(nil), input.Observations...)
	for i := range input.Controls {
		input.Controls[i].ControlRef = strings.TrimSpace(input.Controls[i].ControlRef)
		input.Controls[i].AdapterVersion = strings.TrimSpace(input.Controls[i].AdapterVersion)
		input.Controls[i].ConfigurationHash = strings.ToLower(strings.TrimSpace(input.Controls[i].ConfigurationHash))
		input.Controls[i].CollectorRef = strings.TrimSpace(input.Controls[i].CollectorRef)
		input.Controls[i].CollectorPublicKey = strings.TrimSpace(input.Controls[i].CollectorPublicKey)
	}
	for i := range input.Cases {
		input.Cases[i].CaseRef = strings.TrimSpace(input.Cases[i].CaseRef)
		input.Cases[i].CaseKind = strings.ToLower(strings.TrimSpace(input.Cases[i].CaseKind))
		input.Cases[i].TechniqueID = strings.TrimSpace(input.Cases[i].TechniqueID)
		input.Cases[i].ControlRef = strings.TrimSpace(input.Cases[i].ControlRef)
		input.Cases[i].ControlConfigurationHash = strings.ToLower(strings.TrimSpace(input.Cases[i].ControlConfigurationHash))
		input.Cases[i].ScenarioRef = strings.TrimSpace(input.Cases[i].ScenarioRef)
		input.Cases[i].ScenarioVersion = strings.TrimSpace(input.Cases[i].ScenarioVersion)
		input.Cases[i].ScenarioContractHash = strings.ToLower(strings.TrimSpace(input.Cases[i].ScenarioContractHash))
		input.Cases[i].Chain = strings.ToLower(strings.TrimSpace(input.Cases[i].Chain))
		input.Cases[i].ExecutionMode = strings.ToLower(strings.TrimSpace(input.Cases[i].ExecutionMode))
		input.Cases[i].ExecutionRef = strings.TrimSpace(input.Cases[i].ExecutionRef)
		input.Cases[i].ExecutionHash = strings.ToLower(strings.TrimSpace(input.Cases[i].ExecutionHash))
		input.Cases[i].PreStateHash = strings.ToLower(strings.TrimSpace(input.Cases[i].PreStateHash))
		input.Cases[i].PostStateHash = strings.ToLower(strings.TrimSpace(input.Cases[i].PostStateHash))
		input.Cases[i].EvidenceState = strings.ToLower(strings.TrimSpace(input.Cases[i].EvidenceState))
	}
	for i := range input.Observations {
		input.Observations[i].ControlRef = strings.TrimSpace(input.Observations[i].ControlRef)
		input.Observations[i].CollectorRef = strings.TrimSpace(input.Observations[i].CollectorRef)
		input.Observations[i].CaseRef = strings.TrimSpace(input.Observations[i].CaseRef)
		input.Observations[i].Status = strings.ToLower(strings.TrimSpace(input.Observations[i].Status))
		input.Observations[i].ObservationEvidenceRef = strings.TrimSpace(input.Observations[i].ObservationEvidenceRef)
		input.Observations[i].ObservationEvidenceHash = strings.ToLower(strings.TrimSpace(input.Observations[i].ObservationEvidenceHash))
		input.Observations[i].AlertEvidenceRef = strings.TrimSpace(input.Observations[i].AlertEvidenceRef)
		input.Observations[i].AlertEvidenceHash = strings.ToLower(strings.TrimSpace(input.Observations[i].AlertEvidenceHash))
		input.Observations[i].EvidenceState = strings.ToLower(strings.TrimSpace(input.Observations[i].EvidenceState))
	}
	sort.Slice(input.Controls, func(i, j int) bool { return input.Controls[i].ControlRef < input.Controls[j].ControlRef })
	sort.Slice(input.Cases, func(i, j int) bool {
		return defenseValidationObservationKeyV02(input.Cases[i].ControlRef, input.Cases[i].CaseRef) < defenseValidationObservationKeyV02(input.Cases[j].ControlRef, input.Cases[j].CaseRef)
	})
	sort.Slice(input.Observations, func(i, j int) bool {
		return defenseValidationObservationKeyV02(input.Observations[i].ControlRef, input.Observations[i].CaseRef) < defenseValidationObservationKeyV02(input.Observations[j].ControlRef, input.Observations[j].CaseRef)
	})
	return input
}

func defenseValidationReportHashV02(report DefenseValidationReportV02) string {
	digest := report
	digest.ReportHash = ""
	digest.RunRef = ""
	digest.Controls = append([]DefenseValidationControlResultV02(nil), report.Controls...)
	for i := range digest.Controls {
		digest.Controls[i].Cases = append([]DefenseValidationCaseResultV02(nil), report.Controls[i].Cases...)
		for j := range digest.Controls[i].Cases {
			digest.Controls[i].Cases[j].EvidenceRefs = nil
		}
	}
	payload, err := json.Marshal(digest)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func defenseValidationObservationKeyV02(controlRef, caseRef string) string {
	return controlRef + "\x00" + caseRef
}

func validDefenseValidationEvidenceStateV02(value string) bool {
	return value == DefenseValidationEvidenceVerifiedV02 || value == DefenseValidationEvidenceObservedV02 || value == DefenseValidationEvidenceUnverifiedV02
}

func validDefenseValidationHashV02(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func sortedUniqueDefenseValidationStringsV02(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			seen[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(seen))
	for value := range seen {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func cloneDefenseValidationInt64V02(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
