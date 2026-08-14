package defense

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

const DefenseValidationRulesetVersion = "koschei-defense-validation-rules-v0.1.0"

const (
	DefenseValidationCaseAttack = "attack"
	DefenseValidationCaseBenign = "benign"
)

const (
	DefenseValidationExecutionFork    = "fork"
	DefenseValidationExecutionSandbox = "sandbox"
)

const (
	DefenseValidationEvidenceVerified   = "verified"
	DefenseValidationEvidenceObserved   = "observed"
	DefenseValidationEvidenceUnverified = "unverified"
)

const (
	DefenseValidationObservationAlerted = "alerted"
	DefenseValidationObservationNoAlert = "no_alert"
)

const (
	DefenseValidationOutcomeCaughtInTime = "caught_in_time"
	DefenseValidationOutcomeCaughtLate   = "caught_late"
	DefenseValidationOutcomeMissed       = "missed"
	DefenseValidationOutcomeFalsePositive = "false_positive"
	DefenseValidationOutcomeClean        = "clean"
	DefenseValidationOutcomeIncomplete   = "incomplete"
)

const (
	DefenseValidationVerdictValidated  = "validated"
	DefenseValidationVerdictFailed     = "failed"
	DefenseValidationVerdictIncomplete = "incomplete"
)

const (
	defenseValidationRuleVerifiedExecution = "DV-R01"
	defenseValidationRuleIndependentAlert   = "DV-R02"
	defenseValidationRuleDetectionDeadline  = "DV-R03"
	defenseValidationRuleMissedAttack       = "DV-R04"
	defenseValidationRuleBenignControl      = "DV-R05"
	defenseValidationRuleCompleteMatrix     = "DV-R06"
)

// DefenseValidationControl identifies one exact security-control configuration.
// ConfigurationHash must change whenever the evaluated control policy changes.
type DefenseValidationControl struct {
	ControlRef       string `json:"control_ref"`
	AdapterVersion   string `json:"adapter_version"`
	ConfigurationHash string `json:"configuration_hash"`
	CollectorRef     string `json:"collector_ref"`
}

// DefenseValidationCase binds one controlled attack or benign control to real
// fork/sandbox execution evidence. A case is not a production-mainnet action.
type DefenseValidationCase struct {
	CaseRef                 string `json:"case_ref"`
	CaseKind                string `json:"case_kind"`
	TechniqueID             string `json:"technique_id"`
	ExecutionMode           string `json:"execution_mode"`
	ExecutionRef            string `json:"execution_ref"`
	ExecutionHash           string `json:"execution_hash"`
	PreStateHash            string `json:"pre_state_hash"`
	PostStateHash           string `json:"post_state_hash"`
	EvidenceState           string `json:"evidence_state"`
	ImpactOffsetMS          *int64 `json:"impact_offset_ms,omitempty"`
	ObservationWindowMS     int64  `json:"observation_window_ms"`
	MainnetTransactionSent  bool   `json:"mainnet_transaction_sent"`
}

// DefenseValidationObservation is produced by an independent collector, not
// by the control under test. Offsets are relative to the case start.
type DefenseValidationObservation struct {
	ControlRef                  string `json:"control_ref"`
	CollectorRef                string `json:"collector_ref"`
	CaseRef                     string `json:"case_ref"`
	Status                      string `json:"status"`
	ObservationEvidenceRef      string `json:"observation_evidence_ref"`
	ObservationEvidenceHash     string `json:"observation_evidence_hash"`
	AlertObservedOffsetMS       *int64 `json:"alert_observed_offset_ms,omitempty"`
	AlertEvidenceRef            string `json:"alert_evidence_ref,omitempty"`
	AlertEvidenceHash           string `json:"alert_evidence_hash,omitempty"`
	ObservationCompletedOffsetMS int64  `json:"observation_completed_offset_ms"`
	EvidenceState               string `json:"evidence_state"`
}

type DefenseValidationInput struct {
	RunRef          string                         `json:"run_ref"`
	ScenarioRef     string                         `json:"scenario_ref"`
	ScenarioVersion string                         `json:"scenario_version"`
	Chain           string                         `json:"chain"`
	RulesetVersion  string                         `json:"ruleset_version"`
	Controls        []DefenseValidationControl     `json:"controls"`
	Cases           []DefenseValidationCase        `json:"cases"`
	Observations    []DefenseValidationObservation `json:"observations"`
}

type DefenseValidationCaseResult struct {
	ControlRef    string   `json:"control_ref"`
	CaseRef       string   `json:"case_ref"`
	CaseKind      string   `json:"case_kind"`
	TechniqueID   string   `json:"technique_id"`
	ExecutionMode string   `json:"execution_mode"`
	ExecutionEvidenceState string `json:"execution_evidence_state"`
	ImpactOffsetMS *int64  `json:"impact_offset_ms,omitempty"`
	ObservationWindowMS int64 `json:"observation_window_ms"`
	ObservationStatus string `json:"observation_status"`
	ObservationEvidenceState string `json:"observation_evidence_state"`
	Outcome       string   `json:"outcome"`
	DetectionMS   *int64   `json:"detection_ms,omitempty"`
	LeadTimeMS    *int64   `json:"lead_time_ms,omitempty"`
	TriggeredRules []string `json:"triggered_rules"`
	EvidenceRefs  []string `json:"evidence_refs"`
	EvidenceHashes []string `json:"evidence_hashes"`
	Limitations   []string `json:"limitations"`
}

type DefenseValidationCounts struct {
	AttackCases     int `json:"attack_cases"`
	BenignCases     int `json:"benign_cases"`
	CaughtInTime    int `json:"caught_in_time"`
	CaughtLate      int `json:"caught_late"`
	Missed          int `json:"missed"`
	FalsePositives  int `json:"false_positives"`
	Clean           int `json:"clean"`
	Incomplete      int `json:"incomplete"`
}

type DefenseValidationControlResult struct {
	ControlRef       string                        `json:"control_ref"`
	AdapterVersion   string                        `json:"adapter_version"`
	ConfigurationHash string                       `json:"configuration_hash"`
	CollectorRef     string                        `json:"collector_ref"`
	Verdict          string                        `json:"verdict"`
	TriggeredRules   []string                      `json:"triggered_rules"`
	Counts           DefenseValidationCounts       `json:"counts"`
	Cases            []DefenseValidationCaseResult `json:"cases"`
}

type DefenseValidationReport struct {
	RunRef              string                           `json:"run_ref"`
	ScenarioRef         string                           `json:"scenario_ref"`
	ScenarioVersion     string                           `json:"scenario_version"`
	Chain               string                           `json:"chain"`
	RulesetVersion      string                           `json:"ruleset_version"`
	Verdict             string                           `json:"verdict"`
	Controls            []DefenseValidationControlResult `json:"controls"`
	ReportHash          string                           `json:"report_hash"`
	MainnetTransactionSent bool                          `json:"mainnet_transaction_sent"`
	VerdictAuthority    bool                             `json:"verdict_authority"`
}

// EvaluateDefenseValidation applies deterministic evidence rules only. It does
// no I/O, starts no process, calls no model and cannot submit a transaction.
func EvaluateDefenseValidation(input DefenseValidationInput) (DefenseValidationReport, error) {
	input = normalizeDefenseValidationInput(input)
	if err := validateDefenseValidationInput(input); err != nil {
		return DefenseValidationReport{}, err
	}

	casesByRef := make(map[string]DefenseValidationCase, len(input.Cases))
	for _, item := range input.Cases {
		casesByRef[item.CaseRef] = item
	}
	observations := make(map[string]DefenseValidationObservation, len(input.Observations))
	for _, item := range input.Observations {
		key := defenseValidationObservationKey(item.ControlRef, item.CaseRef)
		if _, exists := observations[key]; exists {
			return DefenseValidationReport{}, fmt.Errorf("duplicate observation for control %q and case %q", item.ControlRef, item.CaseRef)
		}
		validationCase, exists := casesByRef[item.CaseRef]
		if !exists {
			return DefenseValidationReport{}, fmt.Errorf("observation references unknown case %q", item.CaseRef)
		}
		if item.AlertObservedOffsetMS != nil && *item.AlertObservedOffsetMS > validationCase.ObservationWindowMS {
			return DefenseValidationReport{}, fmt.Errorf("observation alert for case %q falls outside the declared window", item.CaseRef)
		}
		observations[key] = item
	}

	controlRefs := make(map[string]DefenseValidationControl, len(input.Controls))
	for _, control := range input.Controls {
		controlRefs[control.ControlRef] = control
	}
	for _, observation := range input.Observations {
		control, exists := controlRefs[observation.ControlRef]
		if !exists {
			return DefenseValidationReport{}, fmt.Errorf("observation references unknown control %q", observation.ControlRef)
		}
		if observation.CollectorRef != control.CollectorRef {
			return DefenseValidationReport{}, fmt.Errorf("observation collector does not match control %q", observation.ControlRef)
		}
	}

	results := make([]DefenseValidationControlResult, 0, len(input.Controls))
	runVerdict := DefenseValidationVerdictValidated
	for _, control := range input.Controls {
		result := evaluateDefenseValidationControl(control, input.Cases, observations)
		results = append(results, result)
		switch result.Verdict {
		case DefenseValidationVerdictFailed:
			runVerdict = DefenseValidationVerdictFailed
		case DefenseValidationVerdictIncomplete:
			if runVerdict != DefenseValidationVerdictFailed {
				runVerdict = DefenseValidationVerdictIncomplete
			}
		}
	}

	report := DefenseValidationReport{
		RunRef: input.RunRef, ScenarioRef: input.ScenarioRef,
		ScenarioVersion: input.ScenarioVersion, Chain: input.Chain,
		RulesetVersion: input.RulesetVersion, Verdict: runVerdict,
		Controls: results, MainnetTransactionSent: false, VerdictAuthority: false,
	}
	report.ReportHash = defenseValidationReportHash(report)
	return report, nil
}

func evaluateDefenseValidationControl(control DefenseValidationControl, cases []DefenseValidationCase, observations map[string]DefenseValidationObservation) DefenseValidationControlResult {
	result := DefenseValidationControlResult{
		ControlRef: control.ControlRef, AdapterVersion: control.AdapterVersion,
		ConfigurationHash: control.ConfigurationHash, CollectorRef: control.CollectorRef,
		Verdict: DefenseValidationVerdictValidated,
		TriggeredRules: []string{},
		Cases: make([]DefenseValidationCaseResult, 0, len(cases)),
	}
	for _, validationCase := range cases {
		if validationCase.CaseKind == DefenseValidationCaseAttack {
			result.Counts.AttackCases++
		} else {
			result.Counts.BenignCases++
		}
		observation, exists := observations[defenseValidationObservationKey(control.ControlRef, validationCase.CaseRef)]
		caseResult := evaluateDefenseValidationCase(control, validationCase, observation, exists)
		result.Cases = append(result.Cases, caseResult)
		result.TriggeredRules = append(result.TriggeredRules, caseResult.TriggeredRules...)
		switch caseResult.Outcome {
		case DefenseValidationOutcomeCaughtInTime:
			result.Counts.CaughtInTime++
		case DefenseValidationOutcomeCaughtLate:
			result.Counts.CaughtLate++
			result.Verdict = DefenseValidationVerdictFailed
		case DefenseValidationOutcomeMissed:
			result.Counts.Missed++
			result.Verdict = DefenseValidationVerdictFailed
		case DefenseValidationOutcomeFalsePositive:
			result.Counts.FalsePositives++
			result.Verdict = DefenseValidationVerdictFailed
		case DefenseValidationOutcomeClean:
			result.Counts.Clean++
		case DefenseValidationOutcomeIncomplete:
			result.Counts.Incomplete++
			if result.Verdict != DefenseValidationVerdictFailed {
				result.Verdict = DefenseValidationVerdictIncomplete
			}
		}
	}
	if result.Counts.AttackCases == 0 || result.Counts.BenignCases == 0 {
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleCompleteMatrix)
		if result.Verdict != DefenseValidationVerdictFailed {
			result.Verdict = DefenseValidationVerdictIncomplete
		}
	}
	result.TriggeredRules = sortedUniqueDefenseValidationStrings(result.TriggeredRules)
	return result
}

func evaluateDefenseValidationCase(control DefenseValidationControl, validationCase DefenseValidationCase, observation DefenseValidationObservation, observationExists bool) DefenseValidationCaseResult {
	result := DefenseValidationCaseResult{
		ControlRef: control.ControlRef, CaseRef: validationCase.CaseRef,
		CaseKind: validationCase.CaseKind, TechniqueID: validationCase.TechniqueID,
		ExecutionMode: validationCase.ExecutionMode,
		ExecutionEvidenceState: validationCase.EvidenceState,
		ImpactOffsetMS: cloneDefenseValidationInt64(validationCase.ImpactOffsetMS),
		ObservationWindowMS: validationCase.ObservationWindowMS,
		Outcome: DefenseValidationOutcomeIncomplete,
		TriggeredRules: []string{}, EvidenceRefs: []string{}, EvidenceHashes: []string{}, Limitations: []string{},
	}
	if validationCase.EvidenceState != DefenseValidationEvidenceVerified {
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleVerifiedExecution)
		result.Limitations = append(result.Limitations, "case execution evidence is not independently verified")
		return result
	}
	result.EvidenceRefs = append(result.EvidenceRefs, validationCase.ExecutionRef)
	result.EvidenceHashes = append(result.EvidenceHashes, validationCase.ExecutionHash, validationCase.PreStateHash, validationCase.PostStateHash)
	if !observationExists {
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleCompleteMatrix)
		result.Limitations = append(result.Limitations, "independent control observation is missing")
		return result
	}
	result.ObservationStatus = observation.Status
	result.ObservationEvidenceState = observation.EvidenceState
	if observation.EvidenceState != DefenseValidationEvidenceVerified {
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleIndependentAlert)
		result.Limitations = append(result.Limitations, "control observation evidence is not independently verified")
		return result
	}
	result.EvidenceRefs = append(result.EvidenceRefs, observation.ObservationEvidenceRef)
	result.EvidenceHashes = append(result.EvidenceHashes, observation.ObservationEvidenceHash)
	if observation.ObservationCompletedOffsetMS < validationCase.ObservationWindowMS {
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleCompleteMatrix)
		result.Limitations = append(result.Limitations, "observation window did not complete")
		return result
	}
	if observation.AlertEvidenceRef != "" {
		result.EvidenceRefs = append(result.EvidenceRefs, observation.AlertEvidenceRef)
		result.EvidenceHashes = append(result.EvidenceHashes, observation.AlertEvidenceHash)
	}

	if validationCase.CaseKind == DefenseValidationCaseBenign {
		if observation.Status == DefenseValidationObservationAlerted {
			result.Outcome = DefenseValidationOutcomeFalsePositive
			result.DetectionMS = cloneDefenseValidationInt64(observation.AlertObservedOffsetMS)
			result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleBenignControl)
		} else {
			result.Outcome = DefenseValidationOutcomeClean
		}
		result.EvidenceRefs = sortedUniqueDefenseValidationStrings(result.EvidenceRefs)
		result.EvidenceHashes = sortedUniqueDefenseValidationStrings(result.EvidenceHashes)
		return result
	}

	if observation.Status == DefenseValidationObservationNoAlert {
		result.Outcome = DefenseValidationOutcomeMissed
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleMissedAttack)
		result.EvidenceRefs = sortedUniqueDefenseValidationStrings(result.EvidenceRefs)
		result.EvidenceHashes = sortedUniqueDefenseValidationStrings(result.EvidenceHashes)
		return result
	}

	result.DetectionMS = cloneDefenseValidationInt64(observation.AlertObservedOffsetMS)
	leadTime := *validationCase.ImpactOffsetMS - *observation.AlertObservedOffsetMS
	result.LeadTimeMS = &leadTime
	if leadTime >= 0 {
		result.Outcome = DefenseValidationOutcomeCaughtInTime
	} else {
		result.Outcome = DefenseValidationOutcomeCaughtLate
		result.TriggeredRules = append(result.TriggeredRules, defenseValidationRuleDetectionDeadline)
	}
	result.EvidenceRefs = sortedUniqueDefenseValidationStrings(result.EvidenceRefs)
	result.EvidenceHashes = sortedUniqueDefenseValidationStrings(result.EvidenceHashes)
	return result
}

func validateDefenseValidationInput(input DefenseValidationInput) error {
	if input.RunRef == "" || input.ScenarioRef == "" || input.ScenarioVersion == "" || input.Chain == "" {
		return errors.New("run, scenario, scenario version and chain are required")
	}
	if input.RulesetVersion != DefenseValidationRulesetVersion {
		return fmt.Errorf("unsupported defense validation ruleset %q", input.RulesetVersion)
	}
	if len(input.Controls) == 0 || len(input.Cases) == 0 {
		return errors.New("at least one control and one case are required")
	}
	controlRefs := map[string]struct{}{}
	for _, control := range input.Controls {
		if control.ControlRef == "" || control.AdapterVersion == "" || control.CollectorRef == "" || !validDefenseValidationHash(control.ConfigurationHash) {
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
		if item.CaseKind != DefenseValidationCaseAttack && item.CaseKind != DefenseValidationCaseBenign {
			return fmt.Errorf("case %q has unsupported kind %q", item.CaseRef, item.CaseKind)
		}
		if item.ExecutionMode != DefenseValidationExecutionFork && item.ExecutionMode != DefenseValidationExecutionSandbox {
			return fmt.Errorf("case %q must execute in a fork or sandbox", item.CaseRef)
		}
		if !validDefenseValidationEvidenceState(item.EvidenceState) {
			return fmt.Errorf("case %q has unsupported evidence state %q", item.CaseRef, item.EvidenceState)
		}
		if !validDefenseValidationHash(item.ExecutionHash) || !validDefenseValidationHash(item.PreStateHash) || !validDefenseValidationHash(item.PostStateHash) {
			return fmt.Errorf("case %q has invalid execution/state hashes", item.CaseRef)
		}
		if item.ObservationWindowMS <= 0 {
			return fmt.Errorf("case %q has invalid observation window", item.CaseRef)
		}
		if item.MainnetTransactionSent {
			return fmt.Errorf("case %q crossed the no-mainnet boundary", item.CaseRef)
		}
		if item.CaseKind == DefenseValidationCaseAttack {
			if item.ImpactOffsetMS == nil || *item.ImpactOffsetMS < 0 || *item.ImpactOffsetMS > item.ObservationWindowMS {
				return fmt.Errorf("attack case %q has invalid impact deadline", item.CaseRef)
			}
		} else if item.ImpactOffsetMS != nil {
			return fmt.Errorf("benign case %q cannot define an impact deadline", item.CaseRef)
		}
	}
	for _, item := range input.Observations {
		if item.ControlRef == "" || item.CollectorRef == "" || item.CaseRef == "" || item.ObservationEvidenceRef == "" || !validDefenseValidationHash(item.ObservationEvidenceHash) || !validDefenseValidationEvidenceState(item.EvidenceState) {
			return errors.New("observation has incomplete identity or evidence state")
		}
		if item.Status != DefenseValidationObservationAlerted && item.Status != DefenseValidationObservationNoAlert {
			return fmt.Errorf("observation for case %q has unsupported status %q", item.CaseRef, item.Status)
		}
		if item.ObservationCompletedOffsetMS < 0 {
			return fmt.Errorf("observation for case %q has invalid completion offset", item.CaseRef)
		}
		if item.Status == DefenseValidationObservationAlerted {
			if item.AlertObservedOffsetMS == nil || *item.AlertObservedOffsetMS < 0 || *item.AlertObservedOffsetMS > item.ObservationCompletedOffsetMS || item.AlertEvidenceRef == "" || !validDefenseValidationHash(item.AlertEvidenceHash) {
				return fmt.Errorf("alert observation for case %q has incomplete alert evidence", item.CaseRef)
			}
		} else if item.AlertObservedOffsetMS != nil || item.AlertEvidenceRef != "" || item.AlertEvidenceHash != "" {
			return fmt.Errorf("no-alert observation for case %q contains alert evidence", item.CaseRef)
		}
	}
	return nil
}

func normalizeDefenseValidationInput(input DefenseValidationInput) DefenseValidationInput {
	input.RunRef = strings.TrimSpace(input.RunRef)
	input.ScenarioRef = strings.TrimSpace(input.ScenarioRef)
	input.ScenarioVersion = strings.TrimSpace(input.ScenarioVersion)
	input.Chain = strings.ToLower(strings.TrimSpace(input.Chain))
	input.RulesetVersion = strings.TrimSpace(input.RulesetVersion)
	input.Controls = append([]DefenseValidationControl(nil), input.Controls...)
	input.Cases = append([]DefenseValidationCase(nil), input.Cases...)
	input.Observations = append([]DefenseValidationObservation(nil), input.Observations...)
	for index := range input.Controls {
		input.Controls[index].ControlRef = strings.TrimSpace(input.Controls[index].ControlRef)
		input.Controls[index].AdapterVersion = strings.TrimSpace(input.Controls[index].AdapterVersion)
		input.Controls[index].ConfigurationHash = strings.TrimSpace(input.Controls[index].ConfigurationHash)
		input.Controls[index].CollectorRef = strings.TrimSpace(input.Controls[index].CollectorRef)
	}
	for index := range input.Cases {
		input.Cases[index].CaseRef = strings.TrimSpace(input.Cases[index].CaseRef)
		input.Cases[index].CaseKind = strings.ToLower(strings.TrimSpace(input.Cases[index].CaseKind))
		input.Cases[index].TechniqueID = strings.TrimSpace(input.Cases[index].TechniqueID)
		input.Cases[index].ExecutionMode = strings.ToLower(strings.TrimSpace(input.Cases[index].ExecutionMode))
		input.Cases[index].ExecutionRef = strings.TrimSpace(input.Cases[index].ExecutionRef)
		input.Cases[index].ExecutionHash = strings.TrimSpace(input.Cases[index].ExecutionHash)
		input.Cases[index].PreStateHash = strings.TrimSpace(input.Cases[index].PreStateHash)
		input.Cases[index].PostStateHash = strings.TrimSpace(input.Cases[index].PostStateHash)
		input.Cases[index].EvidenceState = strings.ToLower(strings.TrimSpace(input.Cases[index].EvidenceState))
	}
	for index := range input.Observations {
		input.Observations[index].ControlRef = strings.TrimSpace(input.Observations[index].ControlRef)
		input.Observations[index].CollectorRef = strings.TrimSpace(input.Observations[index].CollectorRef)
		input.Observations[index].CaseRef = strings.TrimSpace(input.Observations[index].CaseRef)
		input.Observations[index].Status = strings.ToLower(strings.TrimSpace(input.Observations[index].Status))
		input.Observations[index].ObservationEvidenceRef = strings.TrimSpace(input.Observations[index].ObservationEvidenceRef)
		input.Observations[index].ObservationEvidenceHash = strings.TrimSpace(input.Observations[index].ObservationEvidenceHash)
		input.Observations[index].AlertEvidenceRef = strings.TrimSpace(input.Observations[index].AlertEvidenceRef)
		input.Observations[index].AlertEvidenceHash = strings.TrimSpace(input.Observations[index].AlertEvidenceHash)
		input.Observations[index].EvidenceState = strings.ToLower(strings.TrimSpace(input.Observations[index].EvidenceState))
	}
	sort.Slice(input.Controls, func(i, j int) bool { return input.Controls[i].ControlRef < input.Controls[j].ControlRef })
	sort.Slice(input.Cases, func(i, j int) bool { return input.Cases[i].CaseRef < input.Cases[j].CaseRef })
	sort.Slice(input.Observations, func(i, j int) bool {
		left := defenseValidationObservationKey(input.Observations[i].ControlRef, input.Observations[i].CaseRef)
		right := defenseValidationObservationKey(input.Observations[j].ControlRef, input.Observations[j].CaseRef)
		return left < right
	})
	return input
}

func defenseValidationReportHash(report DefenseValidationReport) string {
	digest := report
	digest.ReportHash = ""
	digest.RunRef = ""
	digest.Controls = append([]DefenseValidationControlResult(nil), report.Controls...)
	for controlIndex := range digest.Controls {
		digest.Controls[controlIndex].Cases = append([]DefenseValidationCaseResult(nil), report.Controls[controlIndex].Cases...)
		for caseIndex := range digest.Controls[controlIndex].Cases {
			digest.Controls[controlIndex].Cases[caseIndex].EvidenceRefs = []string{}
		}
	}
	return hashValue(digest)
}

func defenseValidationObservationKey(controlRef, caseRef string) string {
	return controlRef + "\x00" + caseRef
}

func validDefenseValidationEvidenceState(value string) bool {
	return value == DefenseValidationEvidenceVerified || value == DefenseValidationEvidenceObserved || value == DefenseValidationEvidenceUnverified
}

func validDefenseValidationHash(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != len("sha256:")+64 {
		return false
	}
	for _, character := range strings.TrimPrefix(value, "sha256:") {
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}
	return true
}

func sortedUniqueDefenseValidationStrings(values []string) []string {
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

func cloneDefenseValidationInt64(value *int64) *int64 {
	if value == nil {
		return nil
	}
	clone := *value
	return &clone
}
