package defense

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"koschei/api/internal/executioncontainment"
	"koschei/api/internal/executionproof"
	"koschei/api/internal/securityevidence"
)

const (
	DefenseValidationExecutionAdapterVersionV02   = "koschei-defense-execution-integrity-adapter/v0.2.0"
	DefenseValidationObservationBindingVersionV02 = "koschei-defense-observation-binding/v0.2.0"
	DefenseValidationObservationFindingKindV02    = "defense_validation_observation"
	DefenseValidationObservationSubjectTypeV02    = "defense_validation_case"
)

type DefenseValidationExecutionIntegrityConfigV02 struct {
	SchemaVersion                string `json:"schema_version"`
	ExecutionProofVersion        string `json:"execution_proof_version"`
	ExecutionContainmentVersion  string `json:"execution_containment_version"`
	SafeTxHashMode               string `json:"safe_tx_hash_mode"`
	IndependentCollectorRequired bool   `json:"independent_collector_required"`
	MainnetSubmissionAllowed     bool   `json:"mainnet_submission_allowed"`
	ProductionWiringClaim        bool   `json:"production_wiring_claim"`
}

type DefenseValidationExecutionAdapterInputV02 struct {
	CaseRef                string
	CaseKind               string
	TechniqueID            string
	ExecutionMode          string
	ImpactOffsetMS         *int64
	ObservationWindowMS    int64
	MainnetTransactionSent bool
	ContainmentReceipt     executioncontainment.Receipt
	ExecutionProof         executionproof.Proof
}

type DefenseValidationExecutionEvidenceV02 struct {
	Case                     DefenseValidationCaseV02
	ContainmentDecision      executioncontainment.Decision
	ExecutionProofDecision   executionproof.Decision
	ContainmentReceiptSHA256 string
	ExecutionProofSHA256     string
	ControlSignaled          bool
}

type DefenseValidationObservationBindingV02 struct {
	Version                      string `json:"version"`
	Chain                        string `json:"chain"`
	ControlRef                   string `json:"control_ref"`
	CaseRef                      string `json:"case_ref"`
	Status                       string `json:"status"`
	ExecutionHash                string `json:"execution_hash"`
	AlertObservedOffsetMS        *int64 `json:"alert_observed_offset_ms,omitempty"`
	ObservationCompletedOffsetMS int64  `json:"observation_completed_offset_ms"`
}

func NewExecutionIntegrityControlV02(controlRef, collectorRef string, config DefenseValidationExecutionIntegrityConfigV02) (DefenseValidationControlV02, error) {
	controlRef = strings.TrimSpace(controlRef)
	collectorRef = strings.TrimSpace(collectorRef)
	if controlRef == "" || collectorRef == "" {
		return DefenseValidationControlV02{}, errors.New("control_ref and collector_ref are required")
	}
	if controlRef == collectorRef {
		return DefenseValidationControlV02{}, errors.New("execution integrity control cannot collect its own validation evidence")
	}
	if config.SchemaVersion == "" {
		config.SchemaVersion = DefenseValidationExecutionAdapterVersionV02
	}
	if config.ExecutionProofVersion == "" {
		config.ExecutionProofVersion = executionproof.Version
	}
	if config.ExecutionContainmentVersion == "" {
		config.ExecutionContainmentVersion = executioncontainment.Version
	}
	if config.SafeTxHashMode == "" {
		config.SafeTxHashMode = "local_safe_eip712"
	}
	if config.SchemaVersion != DefenseValidationExecutionAdapterVersionV02 ||
		config.ExecutionProofVersion != executionproof.Version ||
		config.ExecutionContainmentVersion != executioncontainment.Version ||
		config.SafeTxHashMode != "local_safe_eip712" {
		return DefenseValidationControlV02{}, errors.New("unsupported execution integrity adapter configuration")
	}
	if !config.IndependentCollectorRequired {
		return DefenseValidationControlV02{}, errors.New("independent collector is mandatory")
	}
	if config.MainnetSubmissionAllowed {
		return DefenseValidationControlV02{}, errors.New("defense validation control cannot allow mainnet submission")
	}
	if config.ProductionWiringClaim {
		return DefenseValidationControlV02{}, errors.New("execution proof production wiring claim is not established")
	}
	configHash, err := defenseValidationCanonicalHashV02(config)
	if err != nil {
		return DefenseValidationControlV02{}, err
	}
	return DefenseValidationControlV02{
		ControlRef:        controlRef,
		AdapterVersion:    DefenseValidationExecutionAdapterVersionV02,
		ConfigurationHash: configHash,
		CollectorRef:      collectorRef,
	}, nil
}

func AdaptExecutionIntegrityCaseV02(input DefenseValidationExecutionAdapterInputV02) (DefenseValidationExecutionEvidenceV02, error) {
	input.CaseRef = strings.TrimSpace(input.CaseRef)
	input.CaseKind = strings.TrimSpace(input.CaseKind)
	input.TechniqueID = strings.TrimSpace(input.TechniqueID)
	input.ExecutionMode = strings.TrimSpace(input.ExecutionMode)
	if input.CaseRef == "" || input.TechniqueID == "" {
		return DefenseValidationExecutionEvidenceV02{}, errors.New("case_ref and technique_id are required")
	}
	if input.CaseKind != DefenseValidationCaseAttackV02 && input.CaseKind != DefenseValidationCaseBenignV02 {
		return DefenseValidationExecutionEvidenceV02{}, fmt.Errorf("unsupported case kind %q", input.CaseKind)
	}
	if input.ExecutionMode != DefenseValidationExecutionForkV02 && input.ExecutionMode != DefenseValidationExecutionSandboxV02 {
		return DefenseValidationExecutionEvidenceV02{}, errors.New("execution evidence must come from a fork or sandbox")
	}
	if input.MainnetTransactionSent {
		return DefenseValidationExecutionEvidenceV02{}, errors.New("mainnet transaction evidence is forbidden in controlled validation")
	}
	if input.ObservationWindowMS <= 0 {
		return DefenseValidationExecutionEvidenceV02{}, errors.New("observation window must be positive")
	}
	if input.CaseKind == DefenseValidationCaseAttackV02 {
		if input.ImpactOffsetMS == nil || *input.ImpactOffsetMS < 0 || *input.ImpactOffsetMS > input.ObservationWindowMS {
			return DefenseValidationExecutionEvidenceV02{}, errors.New("attack case requires an impact deadline inside the observation window")
		}
	} else if input.ImpactOffsetMS != nil {
		return DefenseValidationExecutionEvidenceV02{}, errors.New("benign case cannot define an impact deadline")
	}

	if !executioncontainment.Verify(input.ContainmentReceipt) {
		return DefenseValidationExecutionEvidenceV02{}, errors.New("execution containment receipt failed recomputation")
	}
	if !input.ContainmentReceipt.Observation.BackendAvailable {
		return DefenseValidationExecutionEvidenceV02{}, errors.New("execution containment backend evidence is unavailable")
	}
	if err := verifyExecutionProofArtifactV02(input.ExecutionProof); err != nil {
		return DefenseValidationExecutionEvidenceV02{}, err
	}
	if err := bindContainmentToExecutionProofV02(input.ContainmentReceipt, input.ExecutionProof); err != nil {
		return DefenseValidationExecutionEvidenceV02{}, err
	}

	executionHash, err := defenseValidationCanonicalHashV02(struct {
		AdapterVersion            string                        `json:"adapter_version"`
		CaseRef                   string                        `json:"case_ref"`
		CaseKind                  string                        `json:"case_kind"`
		TechniqueID               string                        `json:"technique_id"`
		ExecutionMode             string                        `json:"execution_mode"`
		ContainmentReceiptSHA256  string                        `json:"containment_receipt_sha256"`
		ContainmentDecision       executioncontainment.Decision `json:"containment_decision"`
		ExecutionProofSHA256      string                        `json:"execution_proof_sha256"`
		ExecutionProofDecision    executionproof.Decision       `json:"execution_proof_decision"`
		PreStateSHA256            string                        `json:"pre_state_sha256"`
		PostStateSHA256           string                        `json:"post_state_sha256"`
		ObservationWindowMS       int64                         `json:"observation_window_ms"`
		MainnetTransactionSent    bool                          `json:"mainnet_transaction_sent"`
	}{
		AdapterVersion:           DefenseValidationExecutionAdapterVersionV02,
		CaseRef:                  input.CaseRef,
		CaseKind:                 input.CaseKind,
		TechniqueID:              input.TechniqueID,
		ExecutionMode:            input.ExecutionMode,
		ContainmentReceiptSHA256: strings.ToLower(input.ContainmentReceipt.ReceiptSHA256),
		ContainmentDecision:      input.ContainmentReceipt.Decision,
		ExecutionProofSHA256:     strings.ToLower(input.ExecutionProof.EnvelopeSHA256),
		ExecutionProofDecision:   input.ExecutionProof.Evaluation.Decision,
		PreStateSHA256:           strings.ToLower(input.ContainmentReceipt.Observation.PreStateSHA256),
		PostStateSHA256:          strings.ToLower(input.ContainmentReceipt.Observation.PostStateSHA256),
		ObservationWindowMS:      input.ObservationWindowMS,
		MainnetTransactionSent:   false,
	})
	if err != nil {
		return DefenseValidationExecutionEvidenceV02{}, err
	}

	validationCase := DefenseValidationCaseV02{
		CaseRef:                input.CaseRef,
		CaseKind:               input.CaseKind,
		TechniqueID:            input.TechniqueID,
		ExecutionMode:          input.ExecutionMode,
		ExecutionRef:           "defense-execution:" + executionHash,
		ExecutionHash:          executionHash,
		PreStateHash:           strings.ToLower(input.ContainmentReceipt.Observation.PreStateSHA256),
		PostStateHash:          strings.ToLower(input.ContainmentReceipt.Observation.PostStateSHA256),
		EvidenceState:          DefenseValidationEvidenceVerifiedV02,
		ImpactOffsetMS:         cloneDefenseValidationInt64V02(input.ImpactOffsetMS),
		ObservationWindowMS:    input.ObservationWindowMS,
		MainnetTransactionSent: false,
	}

	controlSignaled := input.ContainmentReceipt.Decision != executioncontainment.DecisionRelease ||
		input.ExecutionProof.Evaluation.Decision != executionproof.DecisionAllow
	return DefenseValidationExecutionEvidenceV02{
		Case:                     validationCase,
		ContainmentDecision:      input.ContainmentReceipt.Decision,
		ExecutionProofDecision:   input.ExecutionProof.Evaluation.Decision,
		ContainmentReceiptSHA256: strings.ToLower(input.ContainmentReceipt.ReceiptSHA256),
		ExecutionProofSHA256:     strings.ToLower(input.ExecutionProof.EnvelopeSHA256),
		ControlSignaled:          controlSignaled,
	}, nil
}

func DefenseValidationObservationFindingIDV02(controlRef, caseRef string) string {
	return "dv-observation:" + strings.TrimSpace(controlRef) + ":" + strings.TrimSpace(caseRef)
}

func DefenseValidationObservationBindingDigestV02(binding DefenseValidationObservationBindingV02) (string, error) {
	binding.Version = strings.TrimSpace(binding.Version)
	binding.Chain = strings.ToLower(strings.TrimSpace(binding.Chain))
	binding.ControlRef = strings.TrimSpace(binding.ControlRef)
	binding.CaseRef = strings.TrimSpace(binding.CaseRef)
	binding.Status = strings.TrimSpace(binding.Status)
	binding.ExecutionHash = strings.ToLower(strings.TrimSpace(binding.ExecutionHash))
	if binding.Version == "" {
		binding.Version = DefenseValidationObservationBindingVersionV02
	}
	if binding.Version != DefenseValidationObservationBindingVersionV02 || binding.Chain == "" || binding.ControlRef == "" || binding.CaseRef == "" {
		return "", errors.New("observation binding identity is incomplete")
	}
	if !validDefenseValidationHashV02(binding.ExecutionHash) {
		return "", errors.New("observation binding execution hash is invalid")
	}
	if binding.ObservationCompletedOffsetMS < 0 {
		return "", errors.New("observation completion offset is invalid")
	}
	if binding.Status == DefenseValidationObservationAlertedV02 {
		if binding.AlertObservedOffsetMS == nil || *binding.AlertObservedOffsetMS < 0 || *binding.AlertObservedOffsetMS > binding.ObservationCompletedOffsetMS {
			return "", errors.New("alert observation binding is incomplete")
		}
	} else if binding.Status == DefenseValidationObservationNoAlertV02 {
		if binding.AlertObservedOffsetMS != nil {
			return "", errors.New("no-alert observation binding cannot contain an alert offset")
		}
	} else {
		return "", fmt.Errorf("unsupported observation status %q", binding.Status)
	}
	return defenseValidationCanonicalHashV02(binding)
}

func AdaptSecurityEvidenceObservationV02(
	control DefenseValidationControlV02,
	execution DefenseValidationExecutionEvidenceV02,
	binding DefenseValidationObservationBindingV02,
	event securityevidence.Event,
) (DefenseValidationObservationV02, error) {
	if strings.TrimSpace(control.ControlRef) == "" || strings.TrimSpace(control.CollectorRef) == "" || control.ControlRef == control.CollectorRef {
		return DefenseValidationObservationV02{}, errors.New("control lacks an independent collector identity")
	}
	binding.Chain = strings.ToLower(strings.TrimSpace(binding.Chain))
	binding.ControlRef = strings.TrimSpace(binding.ControlRef)
	binding.CaseRef = strings.TrimSpace(binding.CaseRef)
	binding.Status = strings.TrimSpace(binding.Status)
	binding.ExecutionHash = strings.ToLower(strings.TrimSpace(binding.ExecutionHash))
	if binding.ControlRef != control.ControlRef || binding.CaseRef != execution.Case.CaseRef || !strings.EqualFold(binding.ExecutionHash, execution.Case.ExecutionHash) {
		return DefenseValidationObservationV02{}, errors.New("observation binding does not match control execution evidence")
	}
	expectedStatus := DefenseValidationObservationNoAlertV02
	if execution.ControlSignaled {
		expectedStatus = DefenseValidationObservationAlertedV02
	}
	if binding.Status != expectedStatus {
		return DefenseValidationObservationV02{}, errors.New("independent observation status contradicts verified control decisions")
	}
	if binding.ObservationCompletedOffsetMS < execution.Case.ObservationWindowMS {
		return DefenseValidationObservationV02{}, errors.New("independent observation window did not complete")
	}
	bindingDigest, err := DefenseValidationObservationBindingDigestV02(binding)
	if err != nil {
		return DefenseValidationObservationV02{}, err
	}
	if err := event.Verify(); err != nil {
		return DefenseValidationObservationV02{}, fmt.Errorf("security evidence event verification failed: %w", err)
	}
	canonicalEvent, err := event.Canonical()
	if err != nil {
		return DefenseValidationObservationV02{}, err
	}
	if canonicalEvent.Producer != control.CollectorRef {
		return DefenseValidationObservationV02{}, errors.New("security evidence producer does not match independent collector")
	}
	if canonicalEvent.Subject.Chain != binding.Chain || canonicalEvent.Subject.Type != DefenseValidationObservationSubjectTypeV02 || canonicalEvent.Subject.ID != execution.Case.CaseRef {
		return DefenseValidationObservationV02{}, errors.New("security evidence subject does not match validation case")
	}
	if canonicalEvent.Window.ToUnixMS-canonicalEvent.Window.FromUnixMS < binding.ObservationCompletedOffsetMS {
		return DefenseValidationObservationV02{}, errors.New("security evidence event does not cover the completed observation window")
	}
	if !containsDefenseValidationDigestV02(canonicalEvent.SourceDigests, execution.ContainmentReceiptSHA256) ||
		!containsDefenseValidationDigestV02(canonicalEvent.SourceDigests, execution.ExecutionProofSHA256) {
		return DefenseValidationObservationV02{}, errors.New("security evidence event is not bound to both execution artifacts")
	}

	findingID := DefenseValidationObservationFindingIDV02(control.ControlRef, execution.Case.CaseRef)
	matched := 0
	for _, finding := range canonicalEvent.Findings {
		if finding.ID != findingID || finding.Kind != DefenseValidationObservationFindingKindV02 {
			continue
		}
		matched++
		if finding.State != securityevidence.StateVerified || !strings.EqualFold(finding.EvidenceSHA256, bindingDigest) {
			return DefenseValidationObservationV02{}, errors.New("independent observation finding is not verified against the canonical binding")
		}
	}
	if matched != 1 {
		return DefenseValidationObservationV02{}, errors.New("security evidence event must contain exactly one canonical defense observation finding")
	}

	observation := DefenseValidationObservationV02{
		ControlRef:                   control.ControlRef,
		CollectorRef:                 control.CollectorRef,
		CaseRef:                      execution.Case.CaseRef,
		Status:                       binding.Status,
		ObservationEvidenceRef:       "security-evidence:event:" + strings.ToLower(event.EventSHA256),
		ObservationEvidenceHash:      strings.ToLower(event.EventSHA256),
		AlertObservedOffsetMS:        cloneDefenseValidationInt64V02(binding.AlertObservedOffsetMS),
		ObservationCompletedOffsetMS: binding.ObservationCompletedOffsetMS,
		EvidenceState:                DefenseValidationEvidenceVerifiedV02,
	}
	if binding.Status == DefenseValidationObservationAlertedV02 {
		observation.AlertEvidenceRef = "security-evidence:finding:" + findingID
		observation.AlertEvidenceHash = bindingDigest
	}
	return observation, nil
}

func verifyExecutionProofArtifactV02(proof executionproof.Proof) error {
	recomputed, err := executionproof.Evaluate(proof.Envelope)
	if err != nil {
		return fmt.Errorf("recompute execution proof: %w", err)
	}
	if !strings.EqualFold(recomputed.EnvelopeSHA256, strings.TrimSpace(proof.EnvelopeSHA256)) ||
		recomputed.Evaluation.Decision != proof.Evaluation.Decision ||
		!equalExecutionProofReasonsV02(recomputed.Evaluation.Reasons, proof.Evaluation.Reasons) {
		return errors.New("execution proof artifact failed deterministic recomputation")
	}
	return nil
}

func bindContainmentToExecutionProofV02(receipt executioncontainment.Receipt, proof executionproof.Proof) error {
	approvedSigningRequest := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(proof.Envelope.Authorization.ApprovedSigningRequestID)), "0x")
	if receipt.Input.ChainID != proof.Envelope.Payload.ChainID ||
		!strings.EqualFold(strings.TrimSpace(receipt.Input.Target), strings.TrimSpace(proof.Envelope.Payload.Target)) ||
		!strings.EqualFold(receipt.Input.ApprovedIntentSHA256, approvedSigningRequest) ||
		!strings.EqualFold(receipt.Input.ApprovedPayloadSHA256, proof.Envelope.Payload.ApprovedCalldataSHA256) ||
		!strings.EqualFold(receipt.Input.CandidatePayloadSHA256, proof.Envelope.Payload.GeneratedCalldataSHA256) ||
		!strings.EqualFold(receipt.Input.InvariantSetSHA256, proof.Envelope.Simulation.InvariantSetSHA256) {
		return errors.New("execution containment receipt is not bound to the exact execution proof envelope")
	}
	return nil
}

func equalExecutionProofReasonsV02(a, b []executionproof.ReasonCode) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func containsDefenseValidationDigestV02(values []string, expected string) bool {
	expected = strings.ToLower(strings.TrimSpace(expected))
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), expected) {
			return true
		}
	}
	return false
}

func defenseValidationCanonicalHashV02(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}
