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

func NewExecutionIntegrityControlV02(controlRef, collectorRef string, cfg DefenseValidationExecutionIntegrityConfigV02) (DefenseValidationControlV02, error) {
	controlRef = strings.TrimSpace(controlRef)
	collectorRef = strings.TrimSpace(collectorRef)
	if controlRef == "" || collectorRef == "" || controlRef == collectorRef {
		return DefenseValidationControlV02{}, errors.New("control and independent collector identities are required")
	}
	if cfg.SchemaVersion == "" {
		cfg.SchemaVersion = DefenseValidationExecutionAdapterVersionV02
	}
	if cfg.ExecutionProofVersion == "" {
		cfg.ExecutionProofVersion = executionproof.Version
	}
	if cfg.ExecutionContainmentVersion == "" {
		cfg.ExecutionContainmentVersion = executioncontainment.Version
	}
	if cfg.SafeTxHashMode == "" {
		cfg.SafeTxHashMode = "local_safe_eip712"
	}
	if cfg.SchemaVersion != DefenseValidationExecutionAdapterVersionV02 || cfg.ExecutionProofVersion != executionproof.Version || cfg.ExecutionContainmentVersion != executioncontainment.Version || cfg.SafeTxHashMode != "local_safe_eip712" {
		return DefenseValidationControlV02{}, errors.New("unsupported execution integrity adapter configuration")
	}
	if !cfg.IndependentCollectorRequired {
		return DefenseValidationControlV02{}, errors.New("independent collector is mandatory")
	}
	if cfg.MainnetSubmissionAllowed {
		return DefenseValidationControlV02{}, errors.New("mainnet submission is forbidden in validation")
	}
	if cfg.ProductionWiringClaim {
		return DefenseValidationControlV02{}, errors.New("execution proof production wiring is not established")
	}
	digest, err := defenseValidationCanonicalHashV02(cfg)
	if err != nil {
		return DefenseValidationControlV02{}, err
	}
	return DefenseValidationControlV02{ControlRef: controlRef, AdapterVersion: DefenseValidationExecutionAdapterVersionV02, ConfigurationHash: digest, CollectorRef: collectorRef}, nil
}

func AdaptExecutionIntegrityCaseV02(in DefenseValidationExecutionAdapterInputV02) (DefenseValidationExecutionEvidenceV02, error) {
	in.CaseRef = strings.TrimSpace(in.CaseRef)
	in.CaseKind = strings.TrimSpace(in.CaseKind)
	in.TechniqueID = strings.TrimSpace(in.TechniqueID)
	in.ExecutionMode = strings.TrimSpace(in.ExecutionMode)
	if in.CaseRef == "" || in.TechniqueID == "" {
		return DefenseValidationExecutionEvidenceV02{}, errors.New("case identity is required")
	}
	if in.CaseKind != DefenseValidationCaseAttackV02 && in.CaseKind != DefenseValidationCaseBenignV02 {
		return DefenseValidationExecutionEvidenceV02{}, fmt.Errorf("unsupported case kind %q", in.CaseKind)
	}
	if in.ExecutionMode != DefenseValidationExecutionForkV02 && in.ExecutionMode != DefenseValidationExecutionSandboxV02 {
		return DefenseValidationExecutionEvidenceV02{}, errors.New("execution must be fork or sandbox")
	}
	if in.MainnetTransactionSent {
		return DefenseValidationExecutionEvidenceV02{}, errors.New("mainnet transaction evidence is forbidden")
	}
	if in.ObservationWindowMS <= 0 {
		return DefenseValidationExecutionEvidenceV02{}, errors.New("observation window must be positive")
	}
	if in.CaseKind == DefenseValidationCaseAttackV02 {
		if in.ImpactOffsetMS == nil || *in.ImpactOffsetMS < 0 || *in.ImpactOffsetMS > in.ObservationWindowMS {
			return DefenseValidationExecutionEvidenceV02{}, errors.New("attack deadline must be inside observation window")
		}
	} else if in.ImpactOffsetMS != nil {
		return DefenseValidationExecutionEvidenceV02{}, errors.New("benign case cannot define impact deadline")
	}
	if !executioncontainment.Verify(in.ContainmentReceipt) {
		return DefenseValidationExecutionEvidenceV02{}, errors.New("containment receipt failed recomputation")
	}
	if !in.ContainmentReceipt.Observation.BackendAvailable {
		return DefenseValidationExecutionEvidenceV02{}, errors.New("containment backend evidence unavailable")
	}
	if err := verifyExecutionProofArtifactV02(in.ExecutionProof); err != nil {
		return DefenseValidationExecutionEvidenceV02{}, err
	}
	if err := bindContainmentToExecutionProofV02(in.ContainmentReceipt, in.ExecutionProof); err != nil {
		return DefenseValidationExecutionEvidenceV02{}, err
	}

	executionHash, err := defenseValidationCanonicalHashV02(struct {
		AdapterVersion           string                        `json:"adapter_version"`
		CaseRef                  string                        `json:"case_ref"`
		CaseKind                 string                        `json:"case_kind"`
		TechniqueID              string                        `json:"technique_id"`
		ExecutionMode            string                        `json:"execution_mode"`
		ContainmentReceiptSHA256 string                        `json:"containment_receipt_sha256"`
		ContainmentDecision      executioncontainment.Decision `json:"containment_decision"`
		ExecutionProofSHA256     string                        `json:"execution_proof_sha256"`
		ExecutionProofDecision   executionproof.Decision       `json:"execution_proof_decision"`
		PreStateSHA256           string                        `json:"pre_state_sha256"`
		PostStateSHA256          string                        `json:"post_state_sha256"`
		ObservationWindowMS      int64                         `json:"observation_window_ms"`
		MainnetTransactionSent   bool                          `json:"mainnet_transaction_sent"`
	}{
		DefenseValidationExecutionAdapterVersionV02, in.CaseRef, in.CaseKind, in.TechniqueID, in.ExecutionMode,
		strings.ToLower(in.ContainmentReceipt.ReceiptSHA256), in.ContainmentReceipt.Decision,
		strings.ToLower(in.ExecutionProof.EnvelopeSHA256), in.ExecutionProof.Evaluation.Decision,
		strings.ToLower(in.ContainmentReceipt.Observation.PreStateSHA256), strings.ToLower(in.ContainmentReceipt.Observation.PostStateSHA256),
		in.ObservationWindowMS, false,
	})
	if err != nil {
		return DefenseValidationExecutionEvidenceV02{}, err
	}
	c := DefenseValidationCaseV02{
		CaseRef: in.CaseRef, CaseKind: in.CaseKind, TechniqueID: in.TechniqueID, ExecutionMode: in.ExecutionMode,
		ExecutionRef: "defense-execution:" + executionHash, ExecutionHash: executionHash,
		PreStateHash: strings.ToLower(in.ContainmentReceipt.Observation.PreStateSHA256), PostStateHash: strings.ToLower(in.ContainmentReceipt.Observation.PostStateSHA256),
		EvidenceState: DefenseValidationEvidenceVerifiedV02, ImpactOffsetMS: cloneDefenseValidationInt64V02(in.ImpactOffsetMS),
		ObservationWindowMS: in.ObservationWindowMS, MainnetTransactionSent: false,
	}
	signaled := in.ContainmentReceipt.Decision != executioncontainment.DecisionRelease || in.ExecutionProof.Evaluation.Decision != executionproof.DecisionAllow
	return DefenseValidationExecutionEvidenceV02{Case: c, ContainmentDecision: in.ContainmentReceipt.Decision, ExecutionProofDecision: in.ExecutionProof.Evaluation.Decision, ContainmentReceiptSHA256: strings.ToLower(in.ContainmentReceipt.ReceiptSHA256), ExecutionProofSHA256: strings.ToLower(in.ExecutionProof.EnvelopeSHA256), ControlSignaled: signaled}, nil
}

func DefenseValidationObservationFindingIDV02(controlRef, caseRef string) string {
	return "dv-observation:" + strings.TrimSpace(controlRef) + ":" + strings.TrimSpace(caseRef)
}

func DefenseValidationObservationBindingDigestV02(b DefenseValidationObservationBindingV02) (string, error) {
	b.Version = strings.TrimSpace(b.Version)
	if b.Version == "" {
		b.Version = DefenseValidationObservationBindingVersionV02
	}
	b.Chain = strings.ToLower(strings.TrimSpace(b.Chain))
	b.ControlRef = strings.TrimSpace(b.ControlRef)
	b.CaseRef = strings.TrimSpace(b.CaseRef)
	b.Status = strings.TrimSpace(b.Status)
	b.ExecutionHash = strings.ToLower(strings.TrimSpace(b.ExecutionHash))
	if b.Version != DefenseValidationObservationBindingVersionV02 || b.Chain == "" || b.ControlRef == "" || b.CaseRef == "" || !validDefenseValidationHashV02(b.ExecutionHash) {
		return "", errors.New("observation binding identity is incomplete")
	}
	if b.ObservationCompletedOffsetMS < 0 {
		return "", errors.New("observation completion offset is invalid")
	}
	switch b.Status {
	case DefenseValidationObservationAlertedV02:
		if b.AlertObservedOffsetMS == nil || *b.AlertObservedOffsetMS < 0 || *b.AlertObservedOffsetMS > b.ObservationCompletedOffsetMS {
			return "", errors.New("alert observation binding is incomplete")
		}
	case DefenseValidationObservationNoAlertV02:
		if b.AlertObservedOffsetMS != nil {
			return "", errors.New("no-alert observation cannot include alert offset")
		}
	default:
		return "", fmt.Errorf("unsupported observation status %q", b.Status)
	}
	return defenseValidationCanonicalHashV02(b)
}

func AdaptSecurityEvidenceObservationV02(control DefenseValidationControlV02, execution DefenseValidationExecutionEvidenceV02, binding DefenseValidationObservationBindingV02, event securityevidence.Event) (DefenseValidationObservationV02, error) {
	if control.ControlRef == "" || control.CollectorRef == "" || control.ControlRef == control.CollectorRef {
		return DefenseValidationObservationV02{}, errors.New("independent collector identity is required")
	}
	binding.Chain = strings.ToLower(strings.TrimSpace(binding.Chain))
	binding.ControlRef = strings.TrimSpace(binding.ControlRef)
	binding.CaseRef = strings.TrimSpace(binding.CaseRef)
	binding.Status = strings.TrimSpace(binding.Status)
	binding.ExecutionHash = strings.ToLower(strings.TrimSpace(binding.ExecutionHash))
	if binding.ControlRef != control.ControlRef || binding.CaseRef != execution.Case.CaseRef || !strings.EqualFold(binding.ExecutionHash, execution.Case.ExecutionHash) {
		return DefenseValidationObservationV02{}, errors.New("observation binding does not match execution")
	}
	expected := DefenseValidationObservationNoAlertV02
	if execution.ControlSignaled {
		expected = DefenseValidationObservationAlertedV02
	}
	if binding.Status != expected {
		return DefenseValidationObservationV02{}, errors.New("observation status contradicts verified control decisions")
	}
	if binding.ObservationCompletedOffsetMS < execution.Case.ObservationWindowMS {
		return DefenseValidationObservationV02{}, errors.New("observation window did not complete")
	}
	digest, err := DefenseValidationObservationBindingDigestV02(binding)
	if err != nil {
		return DefenseValidationObservationV02{}, err
	}
	if err := event.Verify(); err != nil {
		return DefenseValidationObservationV02{}, fmt.Errorf("verify security evidence event: %w", err)
	}
	canonical, err := event.Canonical()
	if err != nil {
		return DefenseValidationObservationV02{}, err
	}
	if canonical.Producer != control.CollectorRef {
		return DefenseValidationObservationV02{}, errors.New("event producer is not the independent collector")
	}
	if canonical.Subject.Chain != binding.Chain || canonical.Subject.Type != DefenseValidationObservationSubjectTypeV02 || canonical.Subject.ID != execution.Case.CaseRef {
		return DefenseValidationObservationV02{}, errors.New("event subject does not match validation case")
	}
	if canonical.Window.ToUnixMS-canonical.Window.FromUnixMS < binding.ObservationCompletedOffsetMS {
		return DefenseValidationObservationV02{}, errors.New("event window is incomplete")
	}
	if !containsDefenseValidationDigestV02(canonical.SourceDigests, execution.ContainmentReceiptSHA256) || !containsDefenseValidationDigestV02(canonical.SourceDigests, execution.ExecutionProofSHA256) {
		return DefenseValidationObservationV02{}, errors.New("event is not bound to both execution artifacts")
	}
	findingID := DefenseValidationObservationFindingIDV02(control.ControlRef, execution.Case.CaseRef)
	matched := 0
	for _, f := range canonical.Findings {
		if f.ID != findingID || f.Kind != DefenseValidationObservationFindingKindV02 {
			continue
		}
		matched++
		if f.State != securityevidence.StateVerified || !strings.EqualFold(f.EvidenceSHA256, digest) {
			return DefenseValidationObservationV02{}, errors.New("observation finding is not verified against binding")
		}
	}
	if matched != 1 {
		return DefenseValidationObservationV02{}, errors.New("exactly one canonical observation finding is required")
	}
	out := DefenseValidationObservationV02{ControlRef: control.ControlRef, CollectorRef: control.CollectorRef, CaseRef: execution.Case.CaseRef, Status: binding.Status, ObservationEvidenceRef: "security-evidence:event:" + strings.ToLower(event.EventSHA256), ObservationEvidenceHash: strings.ToLower(event.EventSHA256), AlertObservedOffsetMS: cloneDefenseValidationInt64V02(binding.AlertObservedOffsetMS), ObservationCompletedOffsetMS: binding.ObservationCompletedOffsetMS, EvidenceState: DefenseValidationEvidenceVerifiedV02}
	if binding.Status == DefenseValidationObservationAlertedV02 {
		out.AlertEvidenceRef = "security-evidence:finding:" + findingID
		out.AlertEvidenceHash = digest
	}
	return out, nil
}

func verifyExecutionProofArtifactV02(proof executionproof.Proof) error {
	recomputed, err := executionproof.Evaluate(proof.Envelope)
	if err != nil {
		return fmt.Errorf("recompute execution proof: %w", err)
	}
	if !strings.EqualFold(recomputed.EnvelopeSHA256, proof.EnvelopeSHA256) || recomputed.Evaluation.Decision != proof.Evaluation.Decision || !equalExecutionProofReasonsV02(recomputed.Evaluation.Reasons, proof.Evaluation.Reasons) {
		return errors.New("execution proof failed deterministic recomputation")
	}
	return nil
}

func bindContainmentToExecutionProofV02(receipt executioncontainment.Receipt, proof executionproof.Proof) error {
	approved := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(proof.Envelope.Authorization.ApprovedSigningRequestID)), "0x")
	if receipt.Input.ChainID != proof.Envelope.Payload.ChainID || !strings.EqualFold(receipt.Input.Target, proof.Envelope.Payload.Target) || !strings.EqualFold(receipt.Input.ApprovedIntentSHA256, approved) || !strings.EqualFold(receipt.Input.ApprovedPayloadSHA256, proof.Envelope.Payload.ApprovedCalldataSHA256) || !strings.EqualFold(receipt.Input.CandidatePayloadSHA256, proof.Envelope.Payload.GeneratedCalldataSHA256) || !strings.EqualFold(receipt.Input.InvariantSetSHA256, proof.Envelope.Simulation.InvariantSetSHA256) {
		return errors.New("containment receipt is not bound to exact execution proof")
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
	for _, value := range values {
		if strings.EqualFold(strings.TrimSpace(value), strings.TrimSpace(expected)) {
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
