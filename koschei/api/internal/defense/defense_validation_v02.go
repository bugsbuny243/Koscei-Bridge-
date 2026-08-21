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
)

const (
	DefenseValidationExecutionForkV02    = "fork"
	DefenseValidationExecutionSandboxV02 = "sandbox"
)

const (
	DefenseValidationEvidenceVerifiedV02   = "verified"
	DefenseValidationEvidenceObservedV02   = "observed"
	DefenseValidationEvidenceUnverifiedV02 = "unverified"
)

const (
	DefenseValidationObservationAlertedV02 = "alerted"
	DefenseValidationObservationNoAlertV02 = "no_alert"
)

const (
	DefenseValidationOutcomeCaughtInTimeV02  = "caught_in_time"
	DefenseValidationOutcomeCaughtLateV02    = "caught_late"
	DefenseValidationOutcomeMissedV02        = "missed"
	DefenseValidationOutcomeFalsePositiveV02 = "false_positive"
	DefenseValidationOutcomeCleanV02         = "clean"
	DefenseValidationOutcomeIncompleteV02    = "incomplete"
)

const (
	DefenseValidationVerdictValidatedV02  = "validated"
	DefenseValidationVerdictFailedV02     = "failed"
	DefenseValidationVerdictIncompleteV02 = "incomplete"
)

const (
	defenseValidationRuleVerifiedExecutionV02 = "DV-R01"
	defenseValidationRuleIndependentAlertV02   = "DV-R02"
	defenseValidationRuleDetectionDeadlineV02  = "DV-R03"
	defenseValidationRuleMissedAttackV02       = "DV-R04"
	defenseValidationRuleBenignControlV02      = "DV-R05"
	defenseValidationRuleCompleteMatrixV02     = "DV-R06"
)

// DefenseValidationControlV02 identifies one exact security-control configuration.
// ConfigurationHash must change whenever the evaluated policy/configuration changes.
type DefenseValidationControlV02 struct {
	ControlRef        string `json:"control_ref"`
	AdapterVersion    string `json:"adapter_version"`
	ConfigurationHash string `json:"configuration_hash"`
	CollectorRef      string `json:"collector_ref"`
}

// DefenseValidationCaseV02 binds one controlled attack or benign action to
// verified fork/sandbox execution evidence. Mainnet execution is prohibited.
type DefenseValidationCaseV02 struct {
	CaseRef                string `json:"case_ref"`
	CaseKind               string `json:"case_kind"`
	TechniqueID            string `json:"technique_id"`
	ExecutionMode          string `json:"execution_mode"`
	ExecutionRef           string `json:"execution_ref"`
	ExecutionHash          string `json:"execution_hash"`
	PreStateHash           string `json:"pre_state_hash"`
	PostStateHash          string `json:"post_state_hash"`
	EvidenceState          string `json:"evidence_state"`
	ImpactOffsetMS         *int64 `json:"impact_offset_ms,omitempty"`
	ObservationWindowMS    int64  `json:"observation_window_ms"`
	MainnetTransactionSent bool   `json:"mainnet_transaction_sent"`
}

// DefenseValidationObservationV02 must be produced by an independent collector,
// not by the control under test. Offsets are relative to case start.
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
	RunRef          string                            `json:"run_ref"`
	ScenarioRef     string                            `json:"scenario_ref"`
	ScenarioVersion string                            `json:"scenario_version"`
	Chain           string                            `json:"chain"`
	RulesetVersion  string                            `json:"ruleset_version"`
	Controls        []DefenseValidationControlV02     `json:"controls"`
	Cases           []DefenseValidationCaseV02        `json:"cases"`
	Observations    []DefenseValidationObservationV02 `json:"observations"`
}

type DefenseValidationCaseResultV02 struct {
	ControlRef               string   `json:"control_ref"`
	CaseRef                  string   `json:"case_ref"`
	CaseKind                 string   `json:"case_kind"`
	TechniqueID              string   `json:"technique_id"`
	ExecutionMode            string   `json:"execution_mode"`
	ExecutionEvidenceState   string   `json:"execution_evidence_state"`
	ImpactOffsetMS           *int64   `json:"impact_offset_ms,omitempty"`
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
	ControlRef        string                            `json:"control_ref"`
	AdapterVersion    string                            `json:"adapter_version"`
	ConfigurationHash string                            `json:"configuration_hash"`
	CollectorRef      string                            `json:"collector_ref"`
	Verdict           string                            `json:"verdict"`
	TriggeredRules    []string                          `json:"triggered_rules"`
	Counts            DefenseValidationCountsV02        `json:"counts"`
	Cases             []DefenseValidationCaseResultV02 `json:"cases"`
}

type DefenseValidationReportV02 struct {
	RunRef                  string                                `json:"run_ref"`
	ScenarioRef             string                                `json:"scenario_ref"`
	ScenarioVersion         string                                `json:"scenario_version"`
	Chain                   string                                `json:"chain"`
	RulesetVersion          string                                `json:"ruleset_version"`
	Verdict                 string                                `json:"verdict"`
	Controls                []DefenseValidationControlResultV02 `json:"controls"`
	ReportHash              string                                `json:"report_hash"`
	MainnetTransactionSent  bool                                  `json:"mainnet_transaction_sent"`
	VerdictAuthority        bool                                  `json:"verdict_authority"`
}

// EvaluateDefenseValidationV02 is deterministic and I/O-free. It starts no
// process, calls no model, mutates no control and cannot submit transactions.
func EvaluateDefenseValidationV02(input DefenseValidationInputV02) (DefenseValidationReportV02, error) {
	input = normalizeDefenseValidationInputV02(input)
	if err := validateDefenseValidationInputV02(input); err != nil {
		return DefenseValidationReportV02{}, err
	}

	casesByRef := make(map[string]DefenseValidationCaseV02, len(input.Cases))
	for _, item := range input.Cases {
		casesByRef[item.CaseRef] = item
	}

	observations := make(map[string]DefenseValidationObservationV02, len(input.Observations))
	for _, item := range input.Observations {
		key := defenseValidationObservationKeyV02(item.ControlRef, item.CaseRef)
		if _, exists := observations[key]; exists {
			return DefenseValidationReportV02{}, fmt.Errorf("duplicate observation for control %q and case %q", item.ControlRef, item.CaseRef)
		}
		validationCase, exists := casesByRef[item.CaseRef]
		if !exists {
			return DefenseValidationReportV02{}, fmt.Errorf("observation references unknown case %q", item.CaseRef)
		}
		if item.AlertObservedOffsetMS != nil && *item.AlertObservedOffsetMS > validationCase.ObservationWindowMS {
			return DefenseValidationReportV02{}, fmt.Errorf("observation alert for case %q falls outside the declared window", item.CaseRef)
		}
		observations[key] = item
	}

	controlRefs := make(map[string]DefenseValidationControlV02, len(input.Controls))
	for _, control := range input.Controls {
		controlRefs[control.ControlRef] = control
	}
	for _, observation := range input.Observations {
		control, exists := controlRefs[observation.ControlRef]
		if !exists {
			return DefenseValidationReportV02{}, fmt.Errorf("observation references unknown control %q", observation.ControlRef)
		}
		if observation.CollectorRef != control.CollectorRef {
			return DefenseValidationReportV02{}, fmt.Errorf("observation collector does not match control %q", observation.ControlRef)
		}
	}

	results := make([]DefenseValidationControlResultV02, 0, len(input.Controls))
	runVerdict := DefenseValidationVerdictValidatedV02
	for _, control := range input.Controls {
		result := evaluateDefenseValidationControlV02(control, input.Cases, observations)
		results = append(results, result)
		switch result.Verdict {
		case DefenseValidationVerdictFailedV02:
			runVerdict = DefenseValidationVerdictFailedV02
		case DefenseValidationVerdictIncompleteV02:
			if runVerdict != DefenseValidationVerdictFailedV02 {
				runVerdict = DefenseValidationVerdictIncompleteV02
			}
		}
	}

	report := DefenseValidationReportV02{
		RunRef: input.RunRef,
		ScenarioRef: input.ScenarioRef,
		ScenarioVersion: input.ScenarioVersion,
		Chain: input.Chain,
		RulesetVersion: input.RulesetVersion,
		Verdict: runVerdict,
		Controls: results,
		MainnetTransactionSent: false,
		VerdictAuthority: false,
	}
	report.ReportHash = defenseValidationReportHashV02(report)
	return report, nil
}

func evaluateDefenseValidationControlV02(control DefenseValidationControlV02, cases []DefenseValidationCaseV02, observations map[string]DefenseValidationObservationV02) DefenseValidationControlResultV02 {
	result := DefenseValidationControlResultV02{
		ControlRef: control.ControlRef,
		AdapterVersion: control.AdapterVersion,
		ConfigurationHash: control.ConfigurationHash,
		CollectorRef: control.CollectorRef,
		Verdict: DefenseValidationVerdictValidatedV02,
		TriggeredRules: []string{},
		Cases: make([]DefenseValidationCaseResultV02, 0, len(cases)),
	}

	for _, validationCase := range cases {
		if validationCase.CaseKind == DefenseValidationCaseAttackV02 {
			result.Counts.AttackCases++
		} else {
			result.Counts.BenignCases++
		}

		observation, exists := observations[defenseValidationObservationKeyV02(control.ControlRef, validationCase.CaseRef)]
		caseResult := evaluateDefenseValidationCaseV02(control, validationCase, observation, exists)
		result.Cases = append(result.Cases, caseResult)
		result.TriggeredRules = append(result.TriggeredRules, caseResult.TriggeredRules...)

		switch caseResult.Outcome {
		case DefenseValidationOutcomeCaughtInTimeV02:
			result.Counts.CaughtInTime++
		case DefenseValidationOutcomeCaughtLateV02:
			result.Counts.CaughtLate++
			result.Verdict = DefenseValidationVerdictFailedV02
		case DefenseValidationOutcomeMissedV02:
			result.Counts.Missed++
			result.Verdict = DefenseValidationVerdictFailedV02
		case DefenseValidationOutcomeFalsePositiveV02:
			result.Counts.FalsePositives++
			result.Verdict = DefenseValidationVerdictFailedV02
		case DefenseValidationOutcomeCleanV02:
			result.Counts.Clean++
		case DefenseValidationOutcomeIncompleteV02:
			result.Counts.Incomplete++
			if result.Verdict != DefenseValidationVerdictFailedV02 {
				result.Verdict = DefenseValidationVerdictIncompleteV02
			}
		}
	}

	if result.Counts.AttackCases == 0 || result.Counts.BenignCases == 0 {
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleCompleteMatrixV02)
		if result.Verdict != DefenseValidationVerdictFailedV02 {
			result.Verdict = DefenseValidationVerdictIncompleteV02
		}
	}
	result.TriggeredRules = sortedUniqueDefenseValidationStringsV02(result.TriggeredRules)
	return result
}

func evaluateDefenseValidationCaseV02(control DefenseValidationControlV02, validationCase DefenseValidationCaseV02, observation DefenseValidationObservationV02, observationExists bool) DefenseValidationCaseResultV02 {
	result := DefenseValidationCaseResultV02{
		ControlRef: control.ControlRef,
		CaseRef: validationCase.CaseRef,
		CaseKind: validationCase.CaseKind,
		TechniqueID: validationCase.TechniqueID,
		ExecutionMode: validationCase.ExecutionMode,
		ExecutionEvidenceState: validationCase.EvidenceState,
		ImpactOffsetMS: cloneDefenseValidationInt64V02(validationCase.ImpactOffsetMS),
		ObservationWindowMS: validationCase.ObservationWindowMS,
		Outcome: DefenseValidationOutcomeIncompleteV02,
		TriggeredRules: []string{},
		EvidenceRefs: []string{},
		EvidenceHashes: []string{},
		Limitations: []string{},
	}

	if validationCase.EvidenceState != DefenseValidationEvidenceVerifiedV02 {
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleVerifiedExecutionV02)
		result.Limitations = append(result.Limitations, "case execution evidence is not verified")
		return result
	}
	result.EvidenceRefs = append(result.EvidenceRefs, validationCase.ExecutionRef)
	result.EvidenceHashes = append(result.EvidenceHashes, validationCase.ExecutionHash, validationCase.PreStateHash, validationCase.PostStateHash)

	if !observationExists {
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleCompleteMatrixV02)
		result.Limitations = append(result.Limitations, "independent control observation is missing")
		return result
	}
	result.ObservationStatus = observation.Status
	result.ObservationEvidenceState = observation.EvidenceState
	if observation.EvidenceState != DefenseValidationEvidenceVerifiedV02 {
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleIndependentAlertV02)
		result.Limitations = append(result.Limitations, "control observation evidence is not verified")
		return result
	}
	result.EvidenceRefs = append(result.EvidenceRefs, observation.ObservationEvidenceRef)
	result.EvidenceHashes = append(result.EvidenceHashes, observation.ObservationEvidenceHash)

	if observation.ObservationCompletedOffsetMS < validationCase.ObservationWindowMS {
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleCompleteMatrixV02)
		result.Limitations = append(result.Limitations, "observation window did not complete")
		return result
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
		result.EvidenceRefs = sortedUniqueDefenseValidationStringsV02(result.EvidenceRefs)
		result.EvidenceHashes = sortedUniqueDefenseValidationStringsV02(result.EvidenceHashes)
		return result
	}

	if observation.Status == DefenseValidationObservationNoAlertV02 {
		result.Outcome = DefenseValidationOutcomeMissedV02
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleMissedAttackV02)
		result.EvidenceRefs = sortedUniqueDefenseValidationStringsV02(result.EvidenceRefs)
		result.EvidenceHashes = sortedUniqueDefenseValidationStringsV02(result.EvidenceHashes)
		return result
	}

	result.DetectionMS = cloneDefenseValidationInt64V02(observation.AlertObservedOffsetMS)
	leadTime := *validationCase.ImpactOffsetMS - *observation.AlertObservedOffsetMS
	result.LeadTimeMS = &leadTime
	if leadTime >= 0 {
		result.Outcome = DefenseValidationOutcomeCaughtInTimeV02
	} else {
		result.Outcome = DefenseValidationOutcomeCaughtLateV02
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleDetectionDeadlineV02)
	}
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
	if len(input.Controls) == 0 || len(input.Cases) == 0 {
		return errors.New("at least one control and one case are required")
	}

	controlRefs := map[string]struct{}{}
	for _, control := range input.Controls {
		if control.ControlRef == "" || control.AdapterVersion == "" || control.CollectorRef == "" || !validDefenseValidationHashV02(control.ConfigurationHash) {
			return fmt.Errorf("control %q has incomplete identity evidence", control.ControlRef)
		}
		if control.ControlRef == control.CollectorRef {
			return fmt.Errorf("control %q cannot be its own independent collector", control.ControlRef)
		}
		if _, exists := controlRefs[control.ControlRef]; exists {
			return fmt.Errorf("duplicate control %q", control.ControlRef)
		}
		controlRefs[control.ControlRef] = struct{}{}
	}

	caseRefs := map[string]struct{}{}
	for _, item := range input.Cases {
		if item.CaseRef == "" || item.TechniqueID == "" || item.ExecutionRef == "" {
			return fmt.Errorf("case %q has incomplete identity evidence", item.CaseRef)
		}
		if _, exists := caseRefs[item.CaseRef]; exists {
			return fmt.Errorf("duplicate case %q", item.CaseRef)
		}
		caseRefs[item.CaseRef] = struct{}{}
		if item.CaseKind != DefenseValidationCaseAttackV02 && item.CaseKind != DefenseValidationCaseBenignV02 {
			return fmt.Errorf("case %q has unsupported kind %q", item.CaseRef, item.CaseKind)
		}
		if item.ExecutionMode != DefenseValidationExecutionForkV02 && item.ExecutionMode != DefenseValidationExecutionSandboxV02 {
			return fmt.Errorf("case %q must execute in a fork or sandbox", item.CaseRef)
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
		} else if item.ImpactOffsetMS != nil {
			return fmt.Errorf("benign case %q cannot define an impact deadline", item.CaseRef)
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

func normalizeDefenseValidationInputV02(input DefenseValidationInputV02) DefenseValidationInputV02 {
	input.RunRef = strings.TrimSpace(input.RunRef)
	input.ScenarioRef = strings.TrimSpace(input.ScenarioRef)
	input.ScenarioVersion = strings.TrimSpace(input.ScenarioVersion)
	input.Chain = strings.ToLower(strings.TrimSpace(input.Chain))
	input.RulesetVersion = strings.TrimSpace(input.RulesetVersion)
	input.Controls = append([]DefenseValidationControlV02(nil), input.Controls...)
	input.Cases = append([]DefenseValidationCaseV02(nil), input.Cases...)
	input.Observations = append([]DefenseValidationObservationV02(nil), input.Observations...)

	for index := range input.Controls {
		input.Controls[index].ControlRef = strings.TrimSpace(input.Controls[index].ControlRef)
		input.Controls[index].AdapterVersion = strings.TrimSpace(input.Controls[index].AdapterVersion)
		input.Controls[index].ConfigurationHash = strings.ToLower(strings.TrimSpace(input.Controls[index].ConfigurationHash))
		input.Controls[index].CollectorRef = strings.TrimSpace(input.Controls[index].CollectorRef)
	}
	for index := range input.Cases {
		input.Cases[index].CaseRef = strings.TrimSpace(input.Cases[index].CaseRef)
		input.Cases[index].CaseKind = strings.ToLower(strings.TrimSpace(input.Cases[index].CaseKind))
		input.Cases[index].TechniqueID = strings.TrimSpace(input.Cases[index].TechniqueID)
		input.Cases[index].ExecutionMode = strings.ToLower(strings.TrimSpace(input.Cases[index].ExecutionMode))
		input.Cases[index].ExecutionRef = strings.TrimSpace(input.Cases[index].ExecutionRef)
		input.Cases[index].ExecutionHash = strings.ToLower(strings.TrimSpace(input.Cases[index].ExecutionHash))
		input.Cases[index].PreStateHash = strings.ToLower(strings.TrimSpace(input.Cases[index].PreStateHash))
		input.Cases[index].PostStateHash = strings.ToLower(strings.TrimSpace(input.Cases[index].PostStateHash))
		input.Cases[index].EvidenceState = strings.ToLower(strings.TrimSpace(input.Cases[index].EvidenceState))
	}
	for index := range input.Observations {
		input.Observations[index].ControlRef = strings.TrimSpace(input.Observations[index].ControlRef)
		input.Observations[index].CollectorRef = strings.TrimSpace(input.Observations[index].CollectorRef)
		input.Observations[index].CaseRef = strings.TrimSpace(input.Observations[index].CaseRef)
		input.Observations[index].Status = strings.ToLower(strings.TrimSpace(input.Observations[index].Status))
		input.Observations[index].ObservationEvidenceRef = strings.TrimSpace(input.Observations[index].ObservationEvidenceRef)
		input.Observations[index].ObservationEvidenceHash = strings.ToLower(strings.TrimSpace(input.Observations[index].ObservationEvidenceHash))
		input.Observations[index].AlertEvidenceRef = strings.TrimSpace(input.Observations[index].AlertEvidenceRef)
		input.Observations[index].AlertEvidenceHash = strings.ToLower(strings.TrimSpace(input.Observations[index].AlertEvidenceHash))
		input.Observations[index].EvidenceState = strings.ToLower(strings.TrimSpace(input.Observations[index].EvidenceState))
	}

	sort.Slice(input.Controls, func(i, j int) bool { return input.Controls[i].ControlRef < input.Controls[j].ControlRef })
	sort.Slice(input.Cases, func(i, j int) bool { return input.Cases[i].CaseRef < input.Cases[j].CaseRef })
	sort.Slice(input.Observations, func(i, j int) bool {
		left := defenseValidationObservationKeyV02(input.Observations[i].ControlRef, input.Observations[i].CaseRef)
		right := defenseValidationObservationKeyV02(input.Observations[j].ControlRef, input.Observations[j].CaseRef)
		return left < right
	})
	return input
}

func defenseValidationReportHashV02(report DefenseValidationReportV02) string {
	digest := report
	digest.ReportHash = ""
	digest.RunRef = ""
	digest.Controls = append([]DefenseValidationControlResultV02(nil), report.Controls...)
	for controlIndex := range digest.Controls {
		digest.Controls[controlIndex].Cases = append([]DefenseValidationCaseResultV02(nil), report.Controls[controlIndex].Cases...)
		for caseIndex := range digest.Controls[controlIndex].Cases {
			digest.Controls[controlIndex].Cases[caseIndex].EvidenceRefs = []string{}
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
	set := map[string]struct{}{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			set[value] = struct{}{}
		}
	}
	out := make([]string, 0, len(set))
	for value := range set {
		out = append(out, value)
	}
	sort.Strings(out)
	return out
}

func cloneDefenseValidationInt64V02(value *int64) *int64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
