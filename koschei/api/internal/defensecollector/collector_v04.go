package defensecollector

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"koschei/api/internal/defense"
	"koschei/api/internal/executioncontainment"
	"koschei/api/internal/executionproof"
	"koschei/api/internal/securityevidence"
)

const VersionV04 = "koschei-defense-independent-collector/v0.4"

type RequestV04 struct {
	Version                string                              `json:"version"`
	CollectorRef           string                              `json:"collector_ref"`
	Control                defense.DefenseValidationControlV02 `json:"control"`
	Chain                  string                              `json:"chain"`
	CaseRef                string                              `json:"case_ref"`
	CaseKind               string                              `json:"case_kind"`
	TechniqueID            string                              `json:"technique_id"`
	ExecutionMode          string                              `json:"execution_mode"`
	ImpactOffsetMS         *int64                              `json:"impact_offset_ms,omitempty"`
	ObservationWindowMS    int64                               `json:"observation_window_ms"`
	MainnetTransactionSent bool                                `json:"mainnet_transaction_sent"`
	ContainmentReceipt     executioncontainment.Receipt        `json:"containment_receipt"`
	ExecutionProof         executionproof.Proof                `json:"execution_proof"`
}

type ResultV04 struct {
	Version    string                                         `json:"version"`
	Execution  defense.DefenseValidationExecutionEvidenceV02  `json:"execution"`
	Binding    defense.DefenseValidationObservationBindingV03 `json:"binding"`
	Event      securityevidence.Event                         `json:"event"`
	AlertEvent *securityevidence.Event                        `json:"alert_event,omitempty"`
}

// CollectLiveV04 owns the observation clock. It does not accept caller supplied
// completion timestamps. An alert is valid only when it arrives as a separately
// sealed Security Evidence event during the live observation window.
func CollectLiveV04(ctx context.Context, request RequestV04, alerts <-chan securityevidence.Event) (ResultV04, error) {
	request.Version = strings.TrimSpace(request.Version)
	if request.Version == "" {
		request.Version = VersionV04
	}
	if request.Version != VersionV04 {
		return ResultV04{}, fmt.Errorf("unsupported collector version %q", request.Version)
	}
	request.CollectorRef = strings.TrimSpace(request.CollectorRef)
	request.Chain = strings.ToLower(strings.TrimSpace(request.Chain))
	if request.CollectorRef == "" || request.Chain == "" || request.Control.CollectorRef != request.CollectorRef || request.Control.ControlRef == request.CollectorRef || request.Control.ConfigurationHash == "" {
		return ResultV04{}, errors.New("collector, control and configuration identities are required")
	}
	if request.MainnetTransactionSent || request.ObservationWindowMS <= 0 {
		return ResultV04{}, errors.New("live collector requires positive isolated observation window")
	}

	execution, err := defense.AdaptExecutionIntegrityCaseV02(defense.DefenseValidationExecutionAdapterInputV02{
		CaseRef: request.CaseRef, CaseKind: request.CaseKind, TechniqueID: request.TechniqueID, ExecutionMode: request.ExecutionMode,
		ImpactOffsetMS: cloneInt64V03(request.ImpactOffsetMS), ObservationWindowMS: request.ObservationWindowMS,
		MainnetTransactionSent: request.MainnetTransactionSent, ContainmentReceipt: request.ContainmentReceipt, ExecutionProof: request.ExecutionProof,
	})
	if err != nil {
		return ResultV04{}, fmt.Errorf("recompute execution evidence: %w", err)
	}

	started := time.Now()
	startedMS := started.UnixMilli()
	deadline := time.NewTimer(time.Duration(request.ObservationWindowMS) * time.Millisecond)
	defer deadline.Stop()
	var alertEvent *securityevidence.Event

	for {
		select {
		case <-ctx.Done():
			return ResultV04{}, ctx.Err()
		case event, ok := <-alerts:
			if !ok {
				alerts = nil
				continue
			}
			if alertEvent != nil {
				return ResultV04{}, errors.New("multiple alert events are ambiguous")
			}
			copyEvent := event
			alertEvent = &copyEvent
		case <-deadline.C:
			endedMS := time.Now().UnixMilli()
			completed := endedMS - startedMS
			if completed < request.ObservationWindowMS {
				return ResultV04{}, errors.New("wall clock observation window did not actually elapse")
			}

			status := defense.DefenseValidationObservationNoAlertV02
			var alertOffset *int64
			alertSHA := ""
			if alertEvent != nil {
				if err := alertEvent.Verify(); err != nil {
					return ResultV04{}, fmt.Errorf("verify independently observed alert: %w", err)
				}
				canonical, err := alertEvent.Canonical()
				if err != nil {
					return ResultV04{}, err
				}
				if canonical.Producer == request.Control.ControlRef || canonical.Producer == request.CollectorRef {
					return ResultV04{}, errors.New("alert producer is not independent")
				}
				offset := canonical.Window.ToUnixMS - startedMS
				if offset < 0 || canonical.Window.ToUnixMS > endedMS {
					return ResultV04{}, errors.New("alert was not observed inside live window")
				}
				status = defense.DefenseValidationObservationAlertedV02
				alertOffset = &offset
				alertSHA = strings.ToLower(alertEvent.EventSHA256)
			}

			binding := defense.DefenseValidationObservationBindingV03{
				Version: defense.DefenseValidationObservationBindingVersionV03, Chain: request.Chain,
				ControlRef: request.Control.ControlRef, ControlConfigurationHash: request.Control.ConfigurationHash,
				CaseRef: execution.Case.CaseRef, Status: status, ExecutionHash: execution.Case.ExecutionHash,
				AlertEventSHA256: alertSHA, AlertObservedOffsetMS: alertOffset,
				ObservationStartedUnixMS: startedMS, ObservationEndedUnixMS: endedMS, ObservationCompletedOffsetMS: completed,
			}
			bindingDigest, err := defense.DefenseValidationObservationBindingDigestV03(binding)
			if err != nil {
				return ResultV04{}, fmt.Errorf("bind live observation: %w", err)
			}
			event, err := (securityevidence.Event{
				Producer:      request.CollectorRef,
				Subject:       securityevidence.Subject{Chain: request.Chain, Type: defense.DefenseValidationObservationSubjectTypeV02, ID: execution.Case.CaseRef},
				Window:        securityevidence.ObservationWindow{FromUnixMS: startedMS, ToUnixMS: endedMS},
				SourceDigests: []string{execution.ContainmentReceiptSHA256, execution.ExecutionProofSHA256, request.Control.ConfigurationHash},
				Findings:      []securityevidence.Finding{{ID: defense.DefenseValidationObservationFindingIDV02(request.Control.ControlRef, execution.Case.CaseRef), Kind: defense.DefenseValidationObservationFindingKindV02, State: securityevidence.StateVerified, EvidenceSHA256: bindingDigest, Summary: "Independent collector recomputed execution artifacts and observed the complete live window."}},
			}).Seal()
			if err != nil {
				return ResultV04{}, fmt.Errorf("seal live observation event: %w", err)
			}
			return ResultV04{Version: VersionV04, Execution: execution, Binding: binding, Event: event, AlertEvent: alertEvent}, nil
		}
	}
}

func SealAlertV04(observerRef string, control defense.DefenseValidationControlV02, execution defense.DefenseValidationExecutionEvidenceV02, chain string, observedAt time.Time) (securityevidence.Event, error) {
	observerRef = strings.TrimSpace(observerRef)
	chain = strings.ToLower(strings.TrimSpace(chain))
	if observerRef == "" || observerRef == control.ControlRef || observerRef == control.CollectorRef || chain == "" || control.ConfigurationHash == "" || observedAt.IsZero() {
		return securityevidence.Event{}, errors.New("independent alert observer identity is required")
	}
	observedMS := observedAt.UnixMilli()
	binding := defense.DefenseValidationAlertBindingV03{Version: defense.DefenseValidationAlertBindingVersionV03, Chain: chain, ObserverRef: observerRef, ControlRef: control.ControlRef, ControlConfigurationHash: control.ConfigurationHash, CaseRef: execution.Case.CaseRef, ExecutionHash: execution.Case.ExecutionHash, ObservedUnixMS: observedMS}
	digest, err := defense.DefenseValidationAlertBindingDigestV03(binding)
	if err != nil {
		return securityevidence.Event{}, err
	}
	return (securityevidence.Event{
		Producer:      observerRef,
		Subject:       securityevidence.Subject{Chain: chain, Type: defense.DefenseValidationAlertSubjectTypeV03, ID: execution.Case.CaseRef},
		Window:        securityevidence.ObservationWindow{FromUnixMS: observedMS, ToUnixMS: observedMS},
		SourceDigests: []string{execution.ContainmentReceiptSHA256, execution.ExecutionProofSHA256, control.ConfigurationHash},
		Findings:      []securityevidence.Finding{{ID: defense.DefenseValidationAlertFindingIDV03(control.ControlRef, execution.Case.CaseRef), Kind: defense.DefenseValidationAlertFindingKindV03, State: securityevidence.StateVerified, EvidenceSHA256: digest, Summary: "Independent observer recorded a control alert for the exact execution and configuration."}},
	}).Seal()
}
