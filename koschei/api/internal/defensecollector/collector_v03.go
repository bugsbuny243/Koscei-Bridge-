package defensecollector

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"koschei/api/internal/defense"
	"koschei/api/internal/executioncontainment"
	"koschei/api/internal/executionproof"
	"koschei/api/internal/securityevidence"
)

const VersionV03 = "koschei-defense-independent-collector/v0.3"

type RequestV03 struct {
	Version                      string                               `json:"version"`
	CollectorRef                 string                               `json:"collector_ref"`
	Control                      defense.DefenseValidationControlV02  `json:"control"`
	Scenario                     defense.DefenseValidationScenarioV02 `json:"scenario"`
	Chain                        string                               `json:"chain"`
	CaseRef                      string                               `json:"case_ref"`
	CaseKind                     string                               `json:"case_kind"`
	TechniqueID                  string                               `json:"technique_id"`
	ExecutionMode                string                               `json:"execution_mode"`
	ImpactOffsetMS               *int64                               `json:"impact_offset_ms,omitempty"`
	ObservationWindowMS          int64                                `json:"observation_window_ms"`
	ObservationCompletedOffsetMS int64                                `json:"observation_completed_offset_ms"`
	AlertObservedOffsetMS        *int64                               `json:"alert_observed_offset_ms,omitempty"`
	WindowFromUnixMS             int64                                `json:"window_from_unix_ms"`
	WindowToUnixMS               int64                                `json:"window_to_unix_ms"`
	MainnetTransactionSent       bool                                 `json:"mainnet_transaction_sent"`
	ContainmentReceipt           executioncontainment.Receipt         `json:"containment_receipt"`
	ExecutionProof               executionproof.Proof                 `json:"execution_proof"`
}

type ResultV03 struct {
	Version   string                                         `json:"version"`
	Execution defense.DefenseValidationExecutionEvidenceV02  `json:"execution"`
	Binding   defense.DefenseValidationObservationBindingV02 `json:"binding"`
	Event     securityevidence.Event                         `json:"event"`
}

func CollectV03(request RequestV03, collectorPrivateKey ed25519.PrivateKey) (ResultV03, error) {
	request.Version = strings.TrimSpace(request.Version)
	if request.Version == "" {
		request.Version = VersionV03
	}
	if request.Version != VersionV03 {
		return ResultV03{}, fmt.Errorf("unsupported collector version %q", request.Version)
	}
	request.CollectorRef = strings.TrimSpace(request.CollectorRef)
	request.Chain = strings.ToLower(strings.TrimSpace(request.Chain))
	if request.CollectorRef == "" || request.Chain == "" {
		return ResultV03{}, errors.New("collector and chain identity are required")
	}
	if request.Control.CollectorRef != request.CollectorRef || request.Control.ControlRef == request.CollectorRef {
		return ResultV03{}, errors.New("collector identity is not independent from control")
	}
	if len(collectorPrivateKey) != ed25519.PrivateKeySize {
		return ResultV03{}, errors.New("collector Ed25519 signing key is required")
	}
	collectorPublicKey := base64.RawURLEncoding.EncodeToString(collectorPrivateKey.Public().(ed25519.PublicKey))
	if collectorPublicKey != request.Control.CollectorPublicKey {
		return ResultV03{}, errors.New("collector signing key does not match control trust configuration")
	}
	if !strings.EqualFold(strings.TrimSpace(request.Scenario.Chain), request.Chain) {
		return ResultV03{}, errors.New("collector chain does not match scenario contract")
	}
	if request.MainnetTransactionSent {
		return ResultV03{}, errors.New("independent validation collector rejects mainnet execution")
	}
	if request.WindowFromUnixMS < 0 || request.WindowToUnixMS < request.WindowFromUnixMS {
		return ResultV03{}, errors.New("collector observation window is invalid")
	}
	if request.ObservationCompletedOffsetMS < request.ObservationWindowMS || request.WindowToUnixMS-request.WindowFromUnixMS < request.ObservationCompletedOffsetMS {
		return ResultV03{}, errors.New("collector observation window is incomplete")
	}

	execution, err := defense.AdaptExecutionIntegrityCaseV02(defense.DefenseValidationExecutionAdapterInputV02{
		CaseRef:                request.CaseRef,
		CaseKind:               request.CaseKind,
		TechniqueID:            request.TechniqueID,
		ExecutionMode:          request.ExecutionMode,
		ImpactOffsetMS:         cloneInt64V03(request.ImpactOffsetMS),
		ObservationWindowMS:    request.ObservationWindowMS,
		MainnetTransactionSent: request.MainnetTransactionSent,
		Control:                request.Control,
		Scenario:               request.Scenario,
		ContainmentReceipt:     request.ContainmentReceipt,
		ExecutionProof:         request.ExecutionProof,
	})
	if err != nil {
		return ResultV03{}, fmt.Errorf("recompute execution evidence: %w", err)
	}

	status := defense.DefenseValidationObservationNoAlertV02
	alert := cloneInt64V03(request.AlertObservedOffsetMS)
	if execution.ControlSignaled {
		status = defense.DefenseValidationObservationAlertedV02
		if alert == nil {
			return ResultV03{}, errors.New("signaled control requires independently observed alert offset")
		}
	} else if alert != nil {
		return ResultV03{}, errors.New("no-alert control cannot carry alert offset")
	}

	binding := defense.DefenseValidationObservationBindingV02{
		Version:                      defense.DefenseValidationObservationBindingVersionV02,
		Chain:                        request.Chain,
		ControlRef:                   request.Control.ControlRef,
		CaseRef:                      execution.Case.CaseRef,
		Status:                       status,
		ExecutionHash:                execution.Case.ExecutionHash,
		AlertObservedOffsetMS:        alert,
		ObservationCompletedOffsetMS: request.ObservationCompletedOffsetMS,
	}
	bindingDigest, err := defense.DefenseValidationObservationBindingDigestV02(binding)
	if err != nil {
		return ResultV03{}, fmt.Errorf("bind independent observation: %w", err)
	}

	event, err := (securityevidence.Event{
		Producer: request.CollectorRef,
		Subject: securityevidence.Subject{
			Chain: request.Chain,
			Type:  defense.DefenseValidationObservationSubjectTypeV02,
			ID:    execution.Case.CaseRef,
		},
		Window: securityevidence.ObservationWindow{FromUnixMS: request.WindowFromUnixMS, ToUnixMS: request.WindowToUnixMS},
		SourceDigests: []string{
			execution.ContainmentReceiptSHA256,
			execution.ExecutionProofSHA256,
		},
		Findings: []securityevidence.Finding{{
			ID:             defense.DefenseValidationObservationFindingIDV02(request.Control.ControlRef, execution.Case.CaseRef),
			Kind:           defense.DefenseValidationObservationFindingKindV02,
			State:          securityevidence.StateVerified,
			EvidenceSHA256: bindingDigest,
			Summary:        "Independent process recomputed the execution artifacts and bound the completed observation window.",
		}},
	}).SignEd25519(collectorPrivateKey)
	if err != nil {
		return ResultV03{}, fmt.Errorf("authenticate independent security evidence: %w", err)
	}

	return ResultV03{Version: VersionV03, Execution: execution, Binding: binding, Event: event}, nil
}

func cloneInt64V03(value *int64) *int64 {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}
