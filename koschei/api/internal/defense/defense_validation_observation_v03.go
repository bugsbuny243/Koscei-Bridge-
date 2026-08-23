package defense

import (
	"errors"
	"fmt"
	"strings"

	"koschei/api/internal/securityevidence"
)

const (
	DefenseValidationObservationBindingVersionV03 = "koschei-defense-observation-binding/v0.3.0"
	DefenseValidationAlertBindingVersionV03       = "koschei-defense-alert-binding/v0.3.0"
	DefenseValidationAlertFindingKindV03          = "defense_validation_alert"
	DefenseValidationAlertSubjectTypeV03          = "defense_validation_alert"
)

type DefenseValidationObservationBindingV03 struct {
	Version                      string `json:"version"`
	Chain                        string `json:"chain"`
	ControlRef                   string `json:"control_ref"`
	ControlConfigurationHash     string `json:"control_configuration_hash"`
	CaseRef                      string `json:"case_ref"`
	Status                       string `json:"status"`
	ExecutionHash                string `json:"execution_hash"`
	AlertEventSHA256             string `json:"alert_event_sha256,omitempty"`
	AlertObservedOffsetMS        *int64 `json:"alert_observed_offset_ms,omitempty"`
	ObservationStartedUnixMS     int64  `json:"observation_started_unix_ms"`
	ObservationEndedUnixMS       int64  `json:"observation_ended_unix_ms"`
	ObservationCompletedOffsetMS int64  `json:"observation_completed_offset_ms"`
}

type DefenseValidationAlertBindingV03 struct {
	Version                  string `json:"version"`
	Chain                    string `json:"chain"`
	ObserverRef              string `json:"observer_ref"`
	ControlRef               string `json:"control_ref"`
	ControlConfigurationHash string `json:"control_configuration_hash"`
	CaseRef                  string `json:"case_ref"`
	ExecutionHash            string `json:"execution_hash"`
	ObservedUnixMS           int64  `json:"observed_unix_ms"`
}

func DefenseValidationAlertFindingIDV03(controlRef, caseRef string) string {
	return "dv-alert:" + strings.TrimSpace(controlRef) + ":" + strings.TrimSpace(caseRef)
}

func DefenseValidationObservationBindingDigestV03(b DefenseValidationObservationBindingV03) (string, error) {
	b.Version = strings.TrimSpace(b.Version)
	b.Chain = strings.ToLower(strings.TrimSpace(b.Chain))
	b.ControlRef = strings.TrimSpace(b.ControlRef)
	b.ControlConfigurationHash = strings.ToLower(strings.TrimSpace(b.ControlConfigurationHash))
	b.CaseRef = strings.TrimSpace(b.CaseRef)
	b.Status = strings.TrimSpace(b.Status)
	b.ExecutionHash = strings.ToLower(strings.TrimSpace(b.ExecutionHash))
	b.AlertEventSHA256 = strings.ToLower(strings.TrimSpace(b.AlertEventSHA256))
	if b.Version != DefenseValidationObservationBindingVersionV03 || b.Chain == "" || b.ControlRef == "" || b.CaseRef == "" || !validDefenseValidationHashV02(b.ControlConfigurationHash) || !validDefenseValidationHashV02(b.ExecutionHash) {
		return "", errors.New("v0.3 observation binding identity is incomplete")
	}
	if b.ObservationStartedUnixMS <= 0 || b.ObservationEndedUnixMS < b.ObservationStartedUnixMS || b.ObservationCompletedOffsetMS != b.ObservationEndedUnixMS-b.ObservationStartedUnixMS {
		return "", errors.New("v0.3 observation clock evidence is invalid")
	}
	switch b.Status {
	case DefenseValidationObservationAlertedV02:
		if !validDefenseValidationHashV02(b.AlertEventSHA256) || b.AlertObservedOffsetMS == nil || *b.AlertObservedOffsetMS < 0 || *b.AlertObservedOffsetMS > b.ObservationCompletedOffsetMS {
			return "", errors.New("v0.3 alerted observation requires bound alert evidence")
		}
	case DefenseValidationObservationNoAlertV02:
		if b.AlertEventSHA256 != "" || b.AlertObservedOffsetMS != nil {
			return "", errors.New("v0.3 no-alert observation cannot carry alert evidence")
		}
	default:
		return "", fmt.Errorf("unsupported observation status %q", b.Status)
	}
	return defenseValidationCanonicalDigestV02(b)
}

func DefenseValidationAlertBindingDigestV03(b DefenseValidationAlertBindingV03) (string, error) {
	b.Version = strings.TrimSpace(b.Version)
	b.Chain = strings.ToLower(strings.TrimSpace(b.Chain))
	b.ObserverRef = strings.TrimSpace(b.ObserverRef)
	b.ControlRef = strings.TrimSpace(b.ControlRef)
	b.ControlConfigurationHash = strings.ToLower(strings.TrimSpace(b.ControlConfigurationHash))
	b.CaseRef = strings.TrimSpace(b.CaseRef)
	b.ExecutionHash = strings.ToLower(strings.TrimSpace(b.ExecutionHash))
	if b.Version != DefenseValidationAlertBindingVersionV03 || b.Chain == "" || b.ObserverRef == "" || b.ControlRef == "" || b.CaseRef == "" || !validDefenseValidationHashV02(b.ControlConfigurationHash) || !validDefenseValidationHashV02(b.ExecutionHash) || b.ObservedUnixMS <= 0 {
		return "", errors.New("v0.3 alert binding identity is incomplete")
	}
	return defenseValidationCanonicalDigestV02(b)
}

func AdaptSecurityEvidenceObservationV03(control DefenseValidationControlV02, execution DefenseValidationExecutionEvidenceV02, binding DefenseValidationObservationBindingV03, event securityevidence.Event, alertEvent *securityevidence.Event) (DefenseValidationObservationV02, error) {
	if control.ControlRef == "" || control.CollectorRef == "" || control.ControlRef == control.CollectorRef || !validDefenseValidationHashV02(control.ConfigurationHash) {
		return DefenseValidationObservationV02{}, errors.New("independent collector and control configuration identity are required")
	}
	if binding.ControlRef != control.ControlRef || !strings.EqualFold(binding.ControlConfigurationHash, control.ConfigurationHash) || binding.CaseRef != execution.Case.CaseRef || !strings.EqualFold(binding.ExecutionHash, execution.Case.ExecutionHash) {
		return DefenseValidationObservationV02{}, errors.New("v0.3 observation binding does not match control and execution")
	}
	if binding.ObservationCompletedOffsetMS < execution.Case.ObservationWindowMS {
		return DefenseValidationObservationV02{}, errors.New("real observation window did not complete")
	}
	digest, err := DefenseValidationObservationBindingDigestV03(binding)
	if err != nil {
		return DefenseValidationObservationV02{}, err
	}
	if err := event.Verify(); err != nil {
		return DefenseValidationObservationV02{}, fmt.Errorf("verify collector event: %w", err)
	}
	canonical, err := event.Canonical()
	if err != nil {
		return DefenseValidationObservationV02{}, err
	}
	if canonical.Producer != control.CollectorRef || canonical.Subject.Chain != strings.ToLower(strings.TrimSpace(binding.Chain)) || canonical.Subject.Type != DefenseValidationObservationSubjectTypeV02 || canonical.Subject.ID != execution.Case.CaseRef {
		return DefenseValidationObservationV02{}, errors.New("collector event identity does not match v0.3 binding")
	}
	if canonical.Window.FromUnixMS != binding.ObservationStartedUnixMS || canonical.Window.ToUnixMS != binding.ObservationEndedUnixMS {
		return DefenseValidationObservationV02{}, errors.New("collector event window does not match observed clock evidence")
	}
	if !containsDefenseValidationDigestV02(canonical.SourceDigests, execution.ContainmentReceiptSHA256) || !containsDefenseValidationDigestV02(canonical.SourceDigests, execution.ExecutionProofSHA256) || !containsDefenseValidationDigestV02(canonical.SourceDigests, control.ConfigurationHash) {
		return DefenseValidationObservationV02{}, errors.New("collector event is not bound to execution artifacts and control configuration")
	}
	findingID := DefenseValidationObservationFindingIDV02(control.ControlRef, execution.Case.CaseRef)
	matched := 0
	for _, f := range canonical.Findings {
		if f.ID == findingID && f.Kind == DefenseValidationObservationFindingKindV02 {
			matched++
			if f.State != securityevidence.StateVerified || !strings.EqualFold(f.EvidenceSHA256, digest) {
				return DefenseValidationObservationV02{}, errors.New("collector finding is not verified against v0.3 binding")
			}
		}
	}
	if matched != 1 {
		return DefenseValidationObservationV02{}, errors.New("exactly one v0.3 collector finding is required")
	}

	out := DefenseValidationObservationV02{
		ControlRef: control.ControlRef, CollectorRef: control.CollectorRef, CaseRef: execution.Case.CaseRef, Status: binding.Status,
		ObservationEvidenceRef: "security-evidence:event:" + strings.ToLower(event.EventSHA256), ObservationEvidenceHash: defenseValidationHashRefV02(event.EventSHA256),
		AlertObservedOffsetMS: cloneDefenseValidationInt64V02(binding.AlertObservedOffsetMS), ObservationCompletedOffsetMS: binding.ObservationCompletedOffsetMS, EvidenceState: DefenseValidationEvidenceVerifiedV02,
	}
	if binding.Status == DefenseValidationObservationAlertedV02 {
		if alertEvent == nil {
			return DefenseValidationObservationV02{}, errors.New("alerted observation requires separate alert event")
		}
		if err := alertEvent.Verify(); err != nil {
			return DefenseValidationObservationV02{}, fmt.Errorf("verify alert event: %w", err)
		}
		alertCanonical, err := alertEvent.Canonical()
		if err != nil {
			return DefenseValidationObservationV02{}, err
		}
		if alertCanonical.Producer == control.ControlRef || alertCanonical.Producer == control.CollectorRef || !strings.EqualFold(alertEvent.EventSHA256, binding.AlertEventSHA256) || alertCanonical.Subject.Chain != strings.ToLower(strings.TrimSpace(binding.Chain)) || alertCanonical.Subject.Type != DefenseValidationAlertSubjectTypeV03 || alertCanonical.Subject.ID != execution.Case.CaseRef {
			return DefenseValidationObservationV02{}, errors.New("alert evidence is not independently bound")
		}
		if alertCanonical.Window.ToUnixMS < binding.ObservationStartedUnixMS || alertCanonical.Window.ToUnixMS > binding.ObservationEndedUnixMS || alertCanonical.Window.ToUnixMS-binding.ObservationStartedUnixMS != *binding.AlertObservedOffsetMS {
			return DefenseValidationObservationV02{}, errors.New("alert evidence timestamp is outside the live observation window")
		}
		if !containsDefenseValidationDigestV02(alertCanonical.SourceDigests, execution.ContainmentReceiptSHA256) || !containsDefenseValidationDigestV02(alertCanonical.SourceDigests, execution.ExecutionProofSHA256) || !containsDefenseValidationDigestV02(alertCanonical.SourceDigests, control.ConfigurationHash) {
			return DefenseValidationObservationV02{}, errors.New("alert event is not bound to exact execution and control configuration")
		}
		expectedAlertDigest, err := DefenseValidationAlertBindingDigestV03(DefenseValidationAlertBindingV03{
			Version:                  DefenseValidationAlertBindingVersionV03,
			Chain:                    alertCanonical.Subject.Chain,
			ObserverRef:              alertCanonical.Producer,
			ControlRef:               control.ControlRef,
			ControlConfigurationHash: control.ConfigurationHash,
			CaseRef:                  execution.Case.CaseRef,
			ExecutionHash:            execution.Case.ExecutionHash,
			ObservedUnixMS:           alertCanonical.Window.ToUnixMS,
		})
		if err != nil {
			return DefenseValidationObservationV02{}, fmt.Errorf("recompute alert binding: %w", err)
		}
		alertFindingID := DefenseValidationAlertFindingIDV03(control.ControlRef, execution.Case.CaseRef)
		alertMatched := 0
		for _, f := range alertCanonical.Findings {
			if f.ID == alertFindingID && f.Kind == DefenseValidationAlertFindingKindV03 {
				alertMatched++
				if f.State != securityevidence.StateVerified || !strings.EqualFold(f.EvidenceSHA256, expectedAlertDigest) {
					return DefenseValidationObservationV02{}, errors.New("alert finding is not verified against independently recomputed binding")
				}
			}
		}
		if alertMatched != 1 {
			return DefenseValidationObservationV02{}, errors.New("exactly one independent alert finding is required")
		}
		out.AlertEvidenceRef = "security-evidence:event:" + strings.ToLower(alertEvent.EventSHA256)
		out.AlertEvidenceHash = defenseValidationHashRefV02(alertEvent.EventSHA256)
	} else if alertEvent != nil {
		return DefenseValidationObservationV02{}, errors.New("no-alert observation cannot carry alert event")
	}
	return out, nil
}
