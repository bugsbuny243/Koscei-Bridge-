package defense

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
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
	CollectorPublicKey           string `json:"collector_public_key"`
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
	Control                DefenseValidationControlV02
	Scenario               DefenseValidationScenarioV02
	ContainmentReceipt     executioncontainment.Receipt
	ExecutionProof         executionproof.Proof
	ApprovedSafeAction     executioncontainment.ActionArtifact
	CandidateSafeAction    executioncontainment.ActionArtifact
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
	collectorPublicKey, err := requireDefenseValidationCollectorPublicKeyV02(cfg.CollectorPublicKey)
	if err != nil {
		return DefenseValidationControlV02{}, fmt.Errorf("independent collector trust: %w", err)
	}
	cfg.CollectorPublicKey = collectorPublicKey
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
	return DefenseValidationControlV02{ControlRef: controlRef, AdapterVersion: DefenseValidationExecutionAdapterVersionV02, ConfigurationHash: digest, CollectorRef: collectorRef, CollectorPublicKey: collectorPublicKey}, nil
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
	control, err := bindDefenseValidationExecutionControlV02(in.Control)
	if err != nil {
		return DefenseValidationExecutionEvidenceV02{}, err
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
	approvedAction, candidateAction, err := bindDefenseValidationSafeActionsV02(in)
	if err != nil {
		return DefenseValidationExecutionEvidenceV02{}, err
	}
	scenarioDigest, detectionDeadline, err := bindDefenseValidationExecutionScenarioV02(in, control, approvedAction, candidateAction)
	if err != nil {
		return DefenseValidationExecutionEvidenceV02{}, err
	}
	controlSignaled, err := validateDefenseValidationSafeCaseSemanticsV02(in)
	if err != nil {
		return DefenseValidationExecutionEvidenceV02{}, err
	}

	executionHash, err := defenseValidationCanonicalHashV02(struct {
		AdapterVersion            string                        `json:"adapter_version"`
		ControlRef                string                        `json:"control_ref"`
		ControlConfigurationHash  string                        `json:"control_configuration_hash"`
		ScenarioRef               string                        `json:"scenario_ref"`
		ScenarioVersion           string                        `json:"scenario_version"`
		ScenarioContractHash      string                        `json:"scenario_contract_hash"`
		Chain                     string                        `json:"chain"`
		ChainID                   uint64                        `json:"chain_id"`
		CaseRef                   string                        `json:"case_ref"`
		CaseKind                  string                        `json:"case_kind"`
		TechniqueID               string                        `json:"technique_id"`
		ExecutionMode             string                        `json:"execution_mode"`
		ContainmentReceiptSHA256  string                        `json:"containment_receipt_sha256"`
		ContainmentDecision       executioncontainment.Decision `json:"containment_decision"`
		ExecutionProofSHA256      string                        `json:"execution_proof_sha256"`
		ExecutionProofDecision    executionproof.Decision       `json:"execution_proof_decision"`
		ApprovedSafeActionSHA256  string                        `json:"approved_safe_action_sha256"`
		CandidateSafeActionSHA256 string                        `json:"candidate_safe_action_sha256"`
		PreStateSHA256            string                        `json:"pre_state_sha256"`
		PostStateSHA256           string                        `json:"post_state_sha256"`
		ImpactOffsetMS            *int64                        `json:"impact_offset_ms,omitempty"`
		DetectionDeadlineMS       *int64                        `json:"detection_deadline_ms,omitempty"`
		ObservationWindowMS       int64                         `json:"observation_window_ms"`
		MainnetTransactionSent    bool                          `json:"mainnet_transaction_sent"`
	}{
		DefenseValidationExecutionAdapterVersionV02, control.ControlRef, control.ConfigurationHash,
		strings.TrimSpace(in.Scenario.ScenarioRef), strings.TrimSpace(in.Scenario.ScenarioVersion), scenarioDigest,
		strings.ToLower(strings.TrimSpace(in.Scenario.Chain)), in.ContainmentReceipt.Input.ChainID,
		in.CaseRef, in.CaseKind, in.TechniqueID, in.ExecutionMode,
		strings.ToLower(in.ContainmentReceipt.ReceiptSHA256), in.ContainmentReceipt.Decision,
		strings.ToLower(in.ExecutionProof.EnvelopeSHA256), in.ExecutionProof.Evaluation.Decision,
		strings.ToLower(in.ApprovedSafeAction.SHA256()), strings.ToLower(in.CandidateSafeAction.SHA256()),
		strings.ToLower(in.ContainmentReceipt.Observation.PreStateSHA256), strings.ToLower(in.ContainmentReceipt.Observation.PostStateSHA256),
		cloneDefenseValidationInt64V02(in.ImpactOffsetMS), cloneDefenseValidationInt64V02(detectionDeadline), in.ObservationWindowMS, false,
	})
	if err != nil {
		return DefenseValidationExecutionEvidenceV02{}, err
	}
	c := DefenseValidationCaseV02{
		CaseRef: in.CaseRef, CaseKind: in.CaseKind, TechniqueID: in.TechniqueID, ExecutionMode: in.ExecutionMode,
		ControlRef: control.ControlRef, ControlConfigurationHash: control.ConfigurationHash,
		ScenarioRef: strings.TrimSpace(in.Scenario.ScenarioRef), ScenarioVersion: strings.TrimSpace(in.Scenario.ScenarioVersion), ScenarioContractHash: scenarioDigest,
		Chain: strings.ToLower(strings.TrimSpace(in.Scenario.Chain)), ChainID: in.ContainmentReceipt.Input.ChainID,
		ExecutionRef: "defense-execution:" + executionHash, ExecutionHash: executionHash,
		PreStateHash: defenseValidationHashRefV02(in.ContainmentReceipt.Observation.PreStateSHA256), PostStateHash: defenseValidationHashRefV02(in.ContainmentReceipt.Observation.PostStateSHA256),
		EvidenceState: DefenseValidationEvidenceVerifiedV02, ImpactOffsetMS: cloneDefenseValidationInt64V02(in.ImpactOffsetMS),
		DetectionDeadlineMS: cloneDefenseValidationInt64V02(detectionDeadline),
		ObservationWindowMS: in.ObservationWindowMS, MainnetTransactionSent: false,
	}
	return DefenseValidationExecutionEvidenceV02{Case: c, ContainmentDecision: in.ContainmentReceipt.Decision, ExecutionProofDecision: in.ExecutionProof.Evaluation.Decision, ContainmentReceiptSHA256: strings.ToLower(in.ContainmentReceipt.ReceiptSHA256), ExecutionProofSHA256: strings.ToLower(in.ExecutionProof.EnvelopeSHA256), ControlSignaled: controlSignaled}, nil
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
	return defenseValidationCanonicalDigestV02(b)
}

func AdaptSecurityEvidenceObservationV02(control DefenseValidationControlV02, execution DefenseValidationExecutionEvidenceV02, binding DefenseValidationObservationBindingV02, event securityevidence.Event) (DefenseValidationObservationV02, error) {
	var err error
	control, err = bindDefenseValidationExecutionControlV02(control)
	if err != nil {
		return DefenseValidationObservationV02{}, err
	}
	if execution.Case.ControlRef != control.ControlRef || !strings.EqualFold(execution.Case.ControlConfigurationHash, control.ConfigurationHash) {
		return DefenseValidationObservationV02{}, errors.New("execution evidence does not match observation control")
	}
	binding.Chain = strings.ToLower(strings.TrimSpace(binding.Chain))
	binding.ControlRef = strings.TrimSpace(binding.ControlRef)
	binding.CaseRef = strings.TrimSpace(binding.CaseRef)
	binding.Status = strings.TrimSpace(binding.Status)
	binding.ExecutionHash = strings.ToLower(strings.TrimSpace(binding.ExecutionHash))
	if binding.Chain != execution.Case.Chain || binding.ControlRef != control.ControlRef || binding.CaseRef != execution.Case.CaseRef || !strings.EqualFold(binding.ExecutionHash, execution.Case.ExecutionHash) {
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
	if err := event.VerifyEd25519(control.CollectorRef, control.CollectorPublicKey); err != nil {
		return DefenseValidationObservationV02{}, fmt.Errorf("authenticate security evidence event: %w", err)
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
	out := DefenseValidationObservationV02{ControlRef: control.ControlRef, CollectorRef: control.CollectorRef, CaseRef: execution.Case.CaseRef, Status: binding.Status, ObservationEvidenceRef: "security-evidence:event:" + strings.ToLower(event.EventSHA256), ObservationEvidenceHash: defenseValidationHashRefV02(event.EventSHA256), AlertObservedOffsetMS: cloneDefenseValidationInt64V02(binding.AlertObservedOffsetMS), ObservationCompletedOffsetMS: binding.ObservationCompletedOffsetMS, EvidenceState: DefenseValidationEvidenceVerifiedV02}
	if binding.Status == DefenseValidationObservationAlertedV02 {
		out.AlertEvidenceRef = "security-evidence:finding:" + findingID
		out.AlertEvidenceHash = defenseValidationHashRefV02(digest)
	}
	return out, nil
}

func bindDefenseValidationExecutionControlV02(control DefenseValidationControlV02) (DefenseValidationControlV02, error) {
	control.ControlRef = strings.TrimSpace(control.ControlRef)
	control.AdapterVersion = strings.TrimSpace(control.AdapterVersion)
	control.ConfigurationHash = strings.ToLower(strings.TrimSpace(control.ConfigurationHash))
	control.CollectorRef = strings.TrimSpace(control.CollectorRef)
	control.CollectorPublicKey = strings.TrimSpace(control.CollectorPublicKey)
	expected, err := NewExecutionIntegrityControlV02(control.ControlRef, control.CollectorRef, DefenseValidationExecutionIntegrityConfigV02{
		CollectorPublicKey:           control.CollectorPublicKey,
		IndependentCollectorRequired: true,
	})
	if err != nil {
		return DefenseValidationControlV02{}, fmt.Errorf("validate execution integrity control: %w", err)
	}
	if control.AdapterVersion != expected.AdapterVersion || !strings.EqualFold(control.ConfigurationHash, expected.ConfigurationHash) {
		return DefenseValidationControlV02{}, errors.New("execution integrity collector trust does not match control configuration")
	}
	return expected, nil
}

func bindDefenseValidationExecutionScenarioV02(in DefenseValidationExecutionAdapterInputV02, control DefenseValidationControlV02, approvedAction, candidateAction executionproof.SafeTransaction) (string, *int64, error) {
	if !defenseValidationScenarioHasCompleteContractV02(in.Scenario) {
		return "", nil, errors.New("execution integrity scenario must retain the complete parsed contract")
	}
	digest, err := DefenseValidationScenarioDigestV02(in.Scenario)
	if err != nil {
		return "", nil, fmt.Errorf("validate execution integrity scenario: %w", err)
	}
	if control.AdapterVersion != DefenseValidationExecutionAdapterVersionV02 || strings.TrimSpace(in.Scenario.ControlContract.ControlClass) != "pre_signing_execution_integrity" {
		return "", nil, errors.New("scenario does not select the execution integrity control")
	}
	if !defenseAuthorityScenarioExecutionModeMatchesV01(in.Scenario.Environment.ExecutionMode, in.ExecutionMode) {
		return "", nil, errors.New("execution integrity scenario mode does not match adapted execution")
	}
	matched := 0
	var detectionDeadline *int64
	for _, scenarioCase := range in.Scenario.Matrix.Cases {
		if strings.TrimSpace(scenarioCase.CaseRef) != in.CaseRef {
			continue
		}
		matched++
		if strings.TrimSpace(scenarioCase.CaseKind) != in.CaseKind || scenarioCase.ObservationWindowMS != in.ObservationWindowMS || !equalDefenseAuthorityInt64PointersV01(scenarioCase.ImpactDeadlineMS, in.ImpactOffsetMS) {
			return "", nil, errors.New("execution integrity evidence does not match its scenario case contract")
		}
		if err := validateDefenseValidationExecutionScenarioCaseBindingV02(in, scenarioCase, approvedAction, candidateAction); err != nil {
			return "", nil, err
		}
		detectionDeadline = cloneDefenseValidationInt64V02(scenarioCase.ExpectedControlBehavior.LatestDetectionOffsetMS)
	}
	if matched != 1 {
		return "", nil, errors.New("execution integrity case is not an exact scenario member")
	}
	return digest, detectionDeadline, nil
}

func bindDefenseValidationSafeActionsV02(in DefenseValidationExecutionAdapterInputV02) (executionproof.SafeTransaction, executionproof.SafeTransaction, error) {
	approved, err := executionproof.DecodeCanonicalSafeActionArtifact(in.ApprovedSafeAction)
	if err != nil {
		return executionproof.SafeTransaction{}, executionproof.SafeTransaction{}, fmt.Errorf("decode approved Safe action: %w", err)
	}
	candidate, err := executionproof.DecodeCanonicalSafeActionArtifact(in.CandidateSafeAction)
	if err != nil {
		return executionproof.SafeTransaction{}, executionproof.SafeTransaction{}, fmt.Errorf("decode candidate Safe action: %w", err)
	}
	if !strings.EqualFold(approved.Safe, candidate.Safe) || approved.ChainID != candidate.ChainID {
		return executionproof.SafeTransaction{}, executionproof.SafeTransaction{}, errors.New("approved and candidate Safe actions do not share the matched Safe and chain")
	}
	if !strings.EqualFold(in.CandidateSafeAction.SHA256(), in.ContainmentReceipt.Input.ActionSHA256) {
		return executionproof.SafeTransaction{}, executionproof.SafeTransaction{}, errors.New("candidate Safe action does not match containment action digest")
	}
	computer := executionproof.NativeSafeTxHashComputer{}
	approvedHash, err := computer.ComputeSafeTxHash(approved)
	if err != nil {
		return executionproof.SafeTransaction{}, executionproof.SafeTransaction{}, fmt.Errorf("compute approved Safe action hash: %w", err)
	}
	candidateHash, err := computer.ComputeSafeTxHash(candidate)
	if err != nil {
		return executionproof.SafeTransaction{}, executionproof.SafeTransaction{}, fmt.Errorf("compute candidate Safe action hash: %w", err)
	}
	approvedPayload := sha256.Sum256(approved.Data)
	candidatePayload := sha256.Sum256(candidate.Data)
	if !strings.EqualFold(strings.TrimPrefix(approvedHash, "0x"), in.ContainmentReceipt.Input.ApprovedIntentSHA256) ||
		!strings.EqualFold(strings.TrimPrefix(candidateHash, "0x"), in.ContainmentReceipt.Input.CandidateIntentSHA256) ||
		!strings.EqualFold(hex.EncodeToString(approvedPayload[:]), in.ContainmentReceipt.Input.ApprovedPayloadSHA256) ||
		!strings.EqualFold(hex.EncodeToString(candidatePayload[:]), in.ContainmentReceipt.Input.CandidatePayloadSHA256) ||
		!strings.EqualFold(strings.TrimPrefix(approvedHash, "0x"), strings.TrimPrefix(in.ExecutionProof.Envelope.Authorization.ApprovedSigningRequestID, "0x")) ||
		approved.ChainID != in.ExecutionProof.Envelope.Payload.ChainID || candidate.ChainID != in.ExecutionProof.Envelope.Payload.ChainID ||
		!strings.EqualFold(candidate.To, in.ExecutionProof.Envelope.Payload.Target) {
		return executionproof.SafeTransaction{}, executionproof.SafeTransaction{}, errors.New("Safe action material does not match containment and execution proof evidence")
	}
	return approved, candidate, nil
}

func validateDefenseValidationExecutionScenarioCaseBindingV02(in DefenseValidationExecutionAdapterInputV02, scenarioCase DefenseValidationScenarioCaseV02, approved, candidate executionproof.SafeTransaction) error {
	if approved.Value.Sign() <= 0 || candidate.Value.Sign() <= 0 {
		return errors.New("Safe treasury scenario requires evidenced native-asset value")
	}
	actual := map[string]any{
		"safe":                  normalizeDefenseValidationEVMAddressV02(approved.Safe),
		"chain_id":              approved.ChainID,
		"treasury_asset":        "native",
		"transfer_amount":       json.Number(approved.Value.String()),
		"observation_window_ms": in.ObservationWindowMS,
	}
	for _, declaredField := range in.Scenario.Matrix.MatchedFields {
		field := strings.TrimSpace(declaredField)
		observed, supported := actual[field]
		if !supported {
			return fmt.Errorf("execution integrity scenario matched field %q has no execution-evidence binding", field)
		}
		expectedJSON, exists := scenarioCase.MatchedValues[field]
		if !exists {
			return fmt.Errorf("execution integrity scenario case is missing matched field %q", field)
		}
		expected, err := canonicalizeDefenseValidationScenarioJSONV02(expectedJSON)
		if err != nil {
			return fmt.Errorf("canonicalize execution integrity matched field %q: %w", field, err)
		}
		observedJSON, err := json.Marshal(observed)
		if err != nil {
			return fmt.Errorf("encode execution integrity matched field %q: %w", field, err)
		}
		if !bytes.Equal(expected, observedJSON) {
			return fmt.Errorf("execution integrity evidence does not match scenario field %q", field)
		}
	}
	return nil
}

func validateDefenseValidationSafeCaseSemanticsV02(in DefenseValidationExecutionAdapterInputV02) (bool, error) {
	if strings.TrimSpace(in.Scenario.Matrix.SingleSecurityDifference) != "approved_intent_and_executable_action_identity" {
		return false, errors.New("execution integrity adapter requires the declared Safe intent/action identity difference")
	}
	actionsMatch := strings.EqualFold(in.ApprovedSafeAction.SHA256(), in.CandidateSafeAction.SHA256())
	intentOrPayloadMismatch := !strings.EqualFold(in.ContainmentReceipt.Input.ApprovedIntentSHA256, in.ContainmentReceipt.Input.CandidateIntentSHA256) ||
		!strings.EqualFold(in.ContainmentReceipt.Input.ApprovedPayloadSHA256, in.ContainmentReceipt.Input.CandidatePayloadSHA256)

	switch in.CaseKind {
	case DefenseValidationCaseAttackV02:
		if actionsMatch || !intentOrPayloadMismatch || in.ContainmentReceipt.Decision != executioncontainment.DecisionContain ||
			!containsDefenseValidationContainmentReasonV02(in.ContainmentReceipt.Reasons, executioncontainment.ReasonIntentMismatch) {
			return false, errors.New("Safe attack did not exercise the scenario-declared intent or payload mismatch")
		}
		for _, reason := range in.ContainmentReceipt.Reasons {
			switch reason {
			case executioncontainment.ReasonIntentMismatch,
				executioncontainment.ReasonAuthorityChanged,
				executioncontainment.ReasonAssetBoundsExceeded,
				executioncontainment.ReasonCodeIntegrityChanged,
				executioncontainment.ReasonHiddenExecutionPath,
				executioncontainment.ReasonInvariantFailed:
			default:
				return false, fmt.Errorf("Safe attack containment includes unrelated reason %q", reason)
			}
		}
		for _, reason := range in.ExecutionProof.Evaluation.Reasons {
			if reason != executionproof.ReasonPayloadMismatch && reason != executionproof.ReasonInvariantFailed {
				return false, fmt.Errorf("Safe attack Execution Proof includes unrelated reason %q", reason)
			}
		}
		return true, nil
	case DefenseValidationCaseBenignV02:
		if !actionsMatch || intentOrPayloadMismatch || in.ContainmentReceipt.Decision != executioncontainment.DecisionRelease || len(in.ContainmentReceipt.Reasons) != 0 ||
			in.ExecutionProof.Evaluation.Decision != executionproof.DecisionAllow || len(in.ExecutionProof.Evaluation.Reasons) != 0 {
			return false, errors.New("Safe benign case requires an identical action, unqualified release, and ALLOW proof")
		}
		return false, nil
	default:
		return false, fmt.Errorf("unsupported case kind %q", in.CaseKind)
	}
}

func containsDefenseValidationContainmentReasonV02(values []executioncontainment.ReasonCode, wanted executioncontainment.ReasonCode) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func normalizeDefenseValidationEVMAddressV02(value string) string {
	return "0x" + strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "0x"))
}

func requireDefenseValidationCollectorPublicKeyV02(value string) (string, error) {
	value = strings.TrimSpace(value)
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != ed25519.PublicKeySize || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return "", errors.New("collector public key is not canonical base64url Ed25519 key material")
	}
	return value, nil
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
	digest, err := defenseValidationCanonicalDigestV02(value)
	if err != nil {
		return "", err
	}
	return defenseValidationHashRefV02(digest), nil
}

func defenseValidationCanonicalDigestV02(value any) (string, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func defenseValidationHashRefV02(value string) string {
	value = strings.ToLower(strings.TrimSpace(value))
	if strings.HasPrefix(value, "sha256:") {
		return value
	}
	return "sha256:" + value
}
