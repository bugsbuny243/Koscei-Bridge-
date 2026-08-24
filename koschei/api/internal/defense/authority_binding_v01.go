package defense

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"koschei/api/internal/executioncontainment"
	"koschei/api/internal/securityevidence"
)

const (
	DefenseAuthorityBindingVersionV01            = "koschei-defense-authority-binding/v0.1.0"
	DefenseAuthorityExecutionAdapterVersionV01   = "koschei-defense-authority-integrity-adapter/v0.1.0"
	DefenseAuthorityObservationBindingVersionV01 = "koschei-defense-authority-observation-binding/v0.1.0"
	DefenseAuthorityEvidenceArtifactVersionV01   = "koschei-defense-authority-evidence/v0.1.0"

	DefenseAuthorityEvidencePrincipalV01     = "principal_execution"
	DefenseAuthorityEvidenceAuthorizationV01 = "authorization_grant"

	DefenseAuthorityReasonPrincipalMismatchV01 = "principal_mismatch"
	DefenseAuthorityReasonSourceMismatchV01    = "source_account_mismatch"
	DefenseAuthorityReasonOperationMismatchV01 = "operation_mismatch"
	DefenseAuthorityReasonAssetMismatchV01     = "asset_mismatch"
)

type DefenseAuthorityEvidenceArtifactV01 struct {
	Version           string `json:"version"`
	EvidenceState     string `json:"evidence_state"`
	EvidenceKind      string `json:"evidence_kind"`
	Producer          string `json:"producer"`
	Chain             string `json:"chain"`
	ChainID           uint64 `json:"chain_id"`
	Principal         string `json:"principal"`
	SourceAccount     string `json:"source_account"`
	Operation         string `json:"operation"`
	Asset             string `json:"asset"`
	CallPayloadSHA256 string `json:"call_payload_sha256"`
	PreStateSHA256    string `json:"pre_state_sha256"`
	PostStateSHA256   string `json:"post_state_sha256"`
	DebitEffectSHA256 string `json:"debit_effect_sha256"`
	Signature         string `json:"signature"`
}

// DefenseAuthorityEvidenceTrustV01 is supplied by the isolated harness or
// runtime configuration. Trust anchors are intentionally not embedded in the
// evidence artifacts they authenticate.
type DefenseAuthorityEvidenceTrustV01 struct {
	PrincipalProducerRef     string `json:"principal_producer_ref"`
	PrincipalPublicKey       string `json:"principal_public_key"`
	AuthorizationProducerRef string `json:"authorization_producer_ref"`
	AuthorizationPublicKey   string `json:"authorization_public_key"`
}

type DefenseAuthorityBindingEvidenceV01 struct {
	Version                     string                              `json:"version"`
	EvidenceState               string                              `json:"evidence_state"`
	Chain                       string                              `json:"chain"`
	ChainID                     uint64                              `json:"chain_id"`
	CallerPrincipal             string                              `json:"caller_principal"`
	DeclaredSourceAccount       string                              `json:"declared_source_account"`
	RequestedOperation          string                              `json:"requested_operation"`
	RequestedAsset              string                              `json:"requested_asset"`
	AuthorizedPrincipal         string                              `json:"authorized_principal"`
	AuthorizedSourceAccount     string                              `json:"authorized_source_account"`
	AuthorizedOperation         string                              `json:"authorized_operation"`
	AuthorizedAsset             string                              `json:"authorized_asset"`
	CallPayloadSHA256           string                              `json:"call_payload_sha256"`
	PrincipalEvidenceSHA256     string                              `json:"principal_evidence_sha256"`
	AuthorizationEvidenceSHA256 string                              `json:"authorization_evidence_sha256"`
	PreStateSHA256              string                              `json:"pre_state_sha256"`
	PostStateSHA256             string                              `json:"post_state_sha256"`
	DebitEffectSHA256           string                              `json:"debit_effect_sha256"`
	PrincipalEvidence           DefenseAuthorityEvidenceArtifactV01 `json:"principal_evidence"`
	AuthorizationEvidence       DefenseAuthorityEvidenceArtifactV01 `json:"authorization_evidence"`
}

type DefenseAuthorityBindingResultV01 struct {
	Version             string                             `json:"version"`
	Evidence            DefenseAuthorityBindingEvidenceV01 `json:"evidence"`
	Preserved           bool                               `json:"preserved"`
	Reasons             []string                           `json:"reasons"`
	EvidenceTrustSHA256 string                             `json:"evidence_trust_sha256"`
	BindingSHA256       string                             `json:"binding_sha256"`
}

type DefenseAuthorityIntegrityConfigV01 struct {
	SchemaVersion                string                           `json:"schema_version"`
	AuthorityBindingVersion      string                           `json:"authority_binding_version"`
	ExecutionContainmentVersion  string                           `json:"execution_containment_version"`
	EvidenceTrust                DefenseAuthorityEvidenceTrustV01 `json:"evidence_trust"`
	CollectorPublicKey           string                           `json:"collector_public_key"`
	IndependentCollectorRequired bool                             `json:"independent_collector_required"`
	MainnetSubmissionAllowed     bool                             `json:"mainnet_submission_allowed"`
	ProductionWiringClaim        bool                             `json:"production_wiring_claim"`
}

type DefenseAuthorityExecutionAdapterInputV01 struct {
	CaseRef                string
	CaseKind               string
	TechniqueID            string
	ExecutionMode          string
	ImpactOffsetMS         *int64
	ObservationWindowMS    int64
	MainnetTransactionSent bool
	Control                DefenseValidationControlV02
	Scenario               DefenseValidationScenarioV02
	EvidenceTrust          DefenseAuthorityEvidenceTrustV01
	Binding                DefenseAuthorityBindingResultV01
	ContainmentReceipt     executioncontainment.Receipt
}

type DefenseAuthorityExecutionEvidenceV01 struct {
	Case                     DefenseValidationCaseV02
	Chain                    string
	ChainID                  uint64
	ContainmentDecision      executioncontainment.Decision
	ContainmentReceiptSHA256 string
	AuthorityBindingSHA256   string
	ControlSignaled          bool
}

type DefenseAuthorityObservationBindingV01 struct {
	Version                      string `json:"version"`
	Chain                        string `json:"chain"`
	ChainID                      uint64 `json:"chain_id"`
	ControlRef                   string `json:"control_ref"`
	CaseRef                      string `json:"case_ref"`
	Status                       string `json:"status"`
	ExecutionHash                string `json:"execution_hash"`
	AlertObservedOffsetMS        *int64 `json:"alert_observed_offset_ms,omitempty"`
	ObservationCompletedOffsetMS int64  `json:"observation_completed_offset_ms"`
}

func EvaluateDefenseAuthorityBindingV01(e DefenseAuthorityBindingEvidenceV01, trusts ...DefenseAuthorityEvidenceTrustV01) (DefenseAuthorityBindingResultV01, error) {
	trust, err := requireDefenseAuthorityEvidenceTrustV01(trusts)
	if err != nil {
		return DefenseAuthorityBindingResultV01{}, err
	}
	e = normalizeDefenseAuthorityBindingEvidenceV01(e)
	if err := validateDefenseAuthorityBindingEvidenceV01(e, trust); err != nil {
		return DefenseAuthorityBindingResultV01{}, err
	}
	trustDigest, err := defenseAuthorityCanonicalSHA256V01(trust)
	if err != nil {
		return DefenseAuthorityBindingResultV01{}, err
	}
	reasons := make([]string, 0, 4)
	if e.CallerPrincipal != e.AuthorizedPrincipal {
		reasons = append(reasons, DefenseAuthorityReasonPrincipalMismatchV01)
	}
	if e.DeclaredSourceAccount != e.AuthorizedSourceAccount {
		reasons = append(reasons, DefenseAuthorityReasonSourceMismatchV01)
	}
	if e.RequestedOperation != e.AuthorizedOperation {
		reasons = append(reasons, DefenseAuthorityReasonOperationMismatchV01)
	}
	if e.RequestedAsset != e.AuthorizedAsset {
		reasons = append(reasons, DefenseAuthorityReasonAssetMismatchV01)
	}
	out := DefenseAuthorityBindingResultV01{
		Version:             DefenseAuthorityBindingVersionV01,
		Evidence:            e,
		Preserved:           len(reasons) == 0,
		Reasons:             reasons,
		EvidenceTrustSHA256: trustDigest,
	}
	digest, err := defenseAuthorityCanonicalSHA256V01(struct {
		Version             string                             `json:"version"`
		Evidence            DefenseAuthorityBindingEvidenceV01 `json:"evidence"`
		Preserved           bool                               `json:"preserved"`
		Reasons             []string                           `json:"reasons"`
		EvidenceTrustSHA256 string                             `json:"evidence_trust_sha256"`
	}{out.Version, out.Evidence, out.Preserved, out.Reasons, out.EvidenceTrustSHA256})
	if err != nil {
		return DefenseAuthorityBindingResultV01{}, err
	}
	out.BindingSHA256 = digest
	return out, nil
}

func VerifyDefenseAuthorityBindingV01(result DefenseAuthorityBindingResultV01, trusts ...DefenseAuthorityEvidenceTrustV01) bool {
	trust, err := requireDefenseAuthorityEvidenceTrustV01(trusts)
	if err != nil || result.Version != DefenseAuthorityBindingVersionV01 || !validDefenseAuthoritySHA256V01(result.EvidenceTrustSHA256) || !validDefenseAuthoritySHA256V01(result.BindingSHA256) {
		return false
	}
	trustDigest, err := defenseAuthorityCanonicalSHA256V01(trust)
	if err != nil || !strings.EqualFold(trustDigest, result.EvidenceTrustSHA256) {
		return false
	}
	recomputed, err := EvaluateDefenseAuthorityBindingV01(result.Evidence, trust)
	if err != nil {
		return false
	}
	return recomputed.Preserved == result.Preserved &&
		equalDefenseAuthorityStringsV01(recomputed.Reasons, result.Reasons) &&
		strings.EqualFold(recomputed.EvidenceTrustSHA256, result.EvidenceTrustSHA256) &&
		strings.EqualFold(recomputed.BindingSHA256, result.BindingSHA256)
}

func ApplyDefenseAuthorityBindingToContainmentV01(observation executioncontainment.Observation, result DefenseAuthorityBindingResultV01, trusts ...DefenseAuthorityEvidenceTrustV01) (executioncontainment.Observation, error) {
	if !VerifyDefenseAuthorityBindingV01(result, trusts...) {
		return executioncontainment.Observation{}, errors.New("authority binding evidence failed deterministic verification")
	}
	observation.AuthorityPreserved = observation.AuthorityPreserved && result.Preserved
	observation.InvariantsPass = observation.InvariantsPass && result.Preserved
	return observation, nil
}

func NewAuthorityIntegrityControlV01(controlRef, collectorRef string, cfg DefenseAuthorityIntegrityConfigV01) (DefenseValidationControlV02, error) {
	controlRef = strings.TrimSpace(controlRef)
	collectorRef = strings.TrimSpace(collectorRef)
	if controlRef == "" || collectorRef == "" || controlRef == collectorRef {
		return DefenseValidationControlV02{}, errors.New("control and independent collector identities are required")
	}
	if cfg.SchemaVersion == "" {
		cfg.SchemaVersion = DefenseAuthorityExecutionAdapterVersionV01
	}
	if cfg.AuthorityBindingVersion == "" {
		cfg.AuthorityBindingVersion = DefenseAuthorityBindingVersionV01
	}
	if cfg.ExecutionContainmentVersion == "" {
		cfg.ExecutionContainmentVersion = executioncontainment.Version
	}
	trust, err := requireDefenseAuthorityEvidenceTrustV01([]DefenseAuthorityEvidenceTrustV01{cfg.EvidenceTrust})
	if err != nil {
		return DefenseValidationControlV02{}, fmt.Errorf("authority integrity evidence trust: %w", err)
	}
	cfg.EvidenceTrust = trust
	collectorPublicKey, err := requireDefenseValidationCollectorPublicKeyV02(cfg.CollectorPublicKey)
	if err != nil {
		return DefenseValidationControlV02{}, fmt.Errorf("independent collector trust: %w", err)
	}
	cfg.CollectorPublicKey = collectorPublicKey
	if cfg.SchemaVersion != DefenseAuthorityExecutionAdapterVersionV01 || cfg.AuthorityBindingVersion != DefenseAuthorityBindingVersionV01 || cfg.ExecutionContainmentVersion != executioncontainment.Version {
		return DefenseValidationControlV02{}, errors.New("unsupported authority integrity adapter configuration")
	}
	if !cfg.IndependentCollectorRequired {
		return DefenseValidationControlV02{}, errors.New("independent collector is mandatory")
	}
	if cfg.MainnetSubmissionAllowed {
		return DefenseValidationControlV02{}, errors.New("mainnet submission is forbidden in validation")
	}
	if cfg.ProductionWiringClaim {
		return DefenseValidationControlV02{}, errors.New("authority integrity production wiring is not established")
	}
	digest, err := defenseAuthorityCanonicalSHA256V01(cfg)
	if err != nil {
		return DefenseValidationControlV02{}, err
	}
	return DefenseValidationControlV02{ControlRef: controlRef, AdapterVersion: DefenseAuthorityExecutionAdapterVersionV01, ConfigurationHash: defenseValidationHashRefV02(digest), CollectorRef: collectorRef, CollectorPublicKey: collectorPublicKey}, nil
}

func AdaptAuthorityIntegrityCaseV01(in DefenseAuthorityExecutionAdapterInputV01) (DefenseAuthorityExecutionEvidenceV01, error) {
	in.CaseRef = strings.TrimSpace(in.CaseRef)
	in.CaseKind = strings.TrimSpace(in.CaseKind)
	in.TechniqueID = strings.TrimSpace(in.TechniqueID)
	in.ExecutionMode = strings.TrimSpace(in.ExecutionMode)
	if in.CaseRef == "" || in.TechniqueID == "" {
		return DefenseAuthorityExecutionEvidenceV01{}, errors.New("case identity is required")
	}
	if in.CaseKind != DefenseValidationCaseAttackV02 && in.CaseKind != DefenseValidationCaseBenignV02 {
		return DefenseAuthorityExecutionEvidenceV01{}, fmt.Errorf("unsupported case kind %q", in.CaseKind)
	}
	if in.ExecutionMode != DefenseValidationExecutionForkV02 && in.ExecutionMode != DefenseValidationExecutionSandboxV02 {
		return DefenseAuthorityExecutionEvidenceV01{}, errors.New("execution must be fork or sandbox")
	}
	if in.MainnetTransactionSent {
		return DefenseAuthorityExecutionEvidenceV01{}, errors.New("mainnet transaction evidence is forbidden")
	}
	if in.ObservationWindowMS <= 0 {
		return DefenseAuthorityExecutionEvidenceV01{}, errors.New("observation window must be positive")
	}
	if in.CaseKind == DefenseValidationCaseAttackV02 {
		if in.ImpactOffsetMS == nil || *in.ImpactOffsetMS < 0 || *in.ImpactOffsetMS > in.ObservationWindowMS {
			return DefenseAuthorityExecutionEvidenceV01{}, errors.New("attack deadline must be inside observation window")
		}
	} else if in.ImpactOffsetMS != nil {
		return DefenseAuthorityExecutionEvidenceV01{}, errors.New("benign case cannot define impact deadline")
	}
	control, err := bindDefenseAuthorityControlV01(in.Control, in.EvidenceTrust)
	if err != nil {
		return DefenseAuthorityExecutionEvidenceV01{}, err
	}
	if !VerifyDefenseAuthorityBindingV01(in.Binding, in.EvidenceTrust) {
		return DefenseAuthorityExecutionEvidenceV01{}, errors.New("authority binding failed deterministic recomputation")
	}
	if !executioncontainment.Verify(in.ContainmentReceipt) || !in.ContainmentReceipt.Observation.BackendAvailable {
		return DefenseAuthorityExecutionEvidenceV01{}, errors.New("containment receipt is unavailable or invalid")
	}
	if err := bindDefenseAuthorityReceiptV01(in.Binding.Evidence, in.ContainmentReceipt); err != nil {
		return DefenseAuthorityExecutionEvidenceV01{}, err
	}
	if err := validateDefenseAuthorityCaseSemanticsV01(in.CaseKind, in.Binding, in.ContainmentReceipt); err != nil {
		return DefenseAuthorityExecutionEvidenceV01{}, err
	}
	scenarioDigest, detectionDeadline, err := bindDefenseAuthorityScenarioV01(in, control)
	if err != nil {
		return DefenseAuthorityExecutionEvidenceV01{}, err
	}

	executionHash, err := defenseAuthorityCanonicalSHA256V01(struct {
		AdapterVersion           string                        `json:"adapter_version"`
		ControlRef               string                        `json:"control_ref"`
		ControlConfigurationHash string                        `json:"control_configuration_hash"`
		ScenarioRef              string                        `json:"scenario_ref"`
		ScenarioVersion          string                        `json:"scenario_version"`
		ScenarioContractHash     string                        `json:"scenario_contract_hash"`
		Chain                    string                        `json:"chain"`
		ChainID                  uint64                        `json:"chain_id"`
		CaseRef                  string                        `json:"case_ref"`
		CaseKind                 string                        `json:"case_kind"`
		TechniqueID              string                        `json:"technique_id"`
		ExecutionMode            string                        `json:"execution_mode"`
		AuthorityBindingSHA256   string                        `json:"authority_binding_sha256"`
		ContainmentReceiptSHA256 string                        `json:"containment_receipt_sha256"`
		ContainmentDecision      executioncontainment.Decision `json:"containment_decision"`
		CallPayloadSHA256        string                        `json:"call_payload_sha256"`
		PreStateSHA256           string                        `json:"pre_state_sha256"`
		PostStateSHA256          string                        `json:"post_state_sha256"`
		DebitEffectSHA256        string                        `json:"debit_effect_sha256"`
		ImpactOffsetMS           *int64                        `json:"impact_offset_ms,omitempty"`
		DetectionDeadlineMS      *int64                        `json:"detection_deadline_ms,omitempty"`
		ObservationWindowMS      int64                         `json:"observation_window_ms"`
	}{
		DefenseAuthorityExecutionAdapterVersionV01, control.ControlRef, control.ConfigurationHash,
		strings.TrimSpace(in.Scenario.ScenarioRef), strings.TrimSpace(in.Scenario.ScenarioVersion), scenarioDigest,
		in.Binding.Evidence.Chain, in.Binding.Evidence.ChainID,
		in.CaseRef, in.CaseKind, in.TechniqueID, in.ExecutionMode,
		strings.ToLower(in.Binding.BindingSHA256), strings.ToLower(in.ContainmentReceipt.ReceiptSHA256), in.ContainmentReceipt.Decision,
		strings.ToLower(in.ContainmentReceipt.Input.CandidatePayloadSHA256), strings.ToLower(in.ContainmentReceipt.Observation.PreStateSHA256),
		strings.ToLower(in.ContainmentReceipt.Observation.PostStateSHA256), strings.ToLower(in.ContainmentReceipt.Observation.EffectSetSHA256),
		cloneDefenseValidationInt64V02(in.ImpactOffsetMS), cloneDefenseValidationInt64V02(detectionDeadline), in.ObservationWindowMS,
	})
	if err != nil {
		return DefenseAuthorityExecutionEvidenceV01{}, err
	}
	validationCase := DefenseValidationCaseV02{
		CaseRef: in.CaseRef, CaseKind: in.CaseKind, TechniqueID: in.TechniqueID, ExecutionMode: in.ExecutionMode,
		ControlRef: control.ControlRef, ControlConfigurationHash: control.ConfigurationHash,
		ScenarioRef: strings.TrimSpace(in.Scenario.ScenarioRef), ScenarioVersion: strings.TrimSpace(in.Scenario.ScenarioVersion), ScenarioContractHash: scenarioDigest,
		Chain: in.Binding.Evidence.Chain, ChainID: in.Binding.Evidence.ChainID,
		ExecutionRef: "defense-authority-execution:" + executionHash, ExecutionHash: defenseValidationHashRefV02(executionHash),
		PreStateHash:  defenseValidationHashRefV02(in.ContainmentReceipt.Observation.PreStateSHA256),
		PostStateHash: defenseValidationHashRefV02(in.ContainmentReceipt.Observation.PostStateSHA256),
		EvidenceState: DefenseValidationEvidenceVerifiedV02, ImpactOffsetMS: cloneDefenseValidationInt64V02(in.ImpactOffsetMS),
		DetectionDeadlineMS: cloneDefenseValidationInt64V02(detectionDeadline),
		ObservationWindowMS: in.ObservationWindowMS, MainnetTransactionSent: false,
	}
	return DefenseAuthorityExecutionEvidenceV01{
		Case: validationCase, Chain: in.Binding.Evidence.Chain, ChainID: in.Binding.Evidence.ChainID,
		ContainmentDecision:      in.ContainmentReceipt.Decision,
		ContainmentReceiptSHA256: strings.ToLower(in.ContainmentReceipt.ReceiptSHA256),
		AuthorityBindingSHA256:   strings.ToLower(in.Binding.BindingSHA256),
		ControlSignaled:          !in.Binding.Preserved,
	}, nil
}

func DefenseAuthorityObservationBindingDigestV01(binding DefenseAuthorityObservationBindingV01) (string, error) {
	binding = normalizeDefenseAuthorityObservationBindingV01(binding)
	if binding.Version != DefenseAuthorityObservationBindingVersionV01 || binding.Chain == "" || binding.ChainID == 0 || binding.ControlRef == "" || binding.CaseRef == "" || !validDefenseValidationHashV02(binding.ExecutionHash) {
		return "", errors.New("authority observation binding identity is incomplete")
	}
	if binding.ObservationCompletedOffsetMS < 0 {
		return "", errors.New("authority observation completion offset is invalid")
	}
	switch binding.Status {
	case DefenseValidationObservationAlertedV02:
		if binding.AlertObservedOffsetMS == nil || *binding.AlertObservedOffsetMS < 0 || *binding.AlertObservedOffsetMS > binding.ObservationCompletedOffsetMS {
			return "", errors.New("authority alert binding is incomplete")
		}
	case DefenseValidationObservationNoAlertV02:
		if binding.AlertObservedOffsetMS != nil {
			return "", errors.New("authority no-alert binding cannot include alert offset")
		}
	default:
		return "", fmt.Errorf("unsupported authority observation status %q", binding.Status)
	}
	return defenseAuthorityCanonicalSHA256V01(binding)
}

func AdaptAuthoritySecurityEvidenceObservationV01(control DefenseValidationControlV02, execution DefenseAuthorityExecutionEvidenceV01, binding DefenseAuthorityObservationBindingV01, event securityevidence.Event, trusts ...DefenseAuthorityEvidenceTrustV01) (DefenseValidationObservationV02, error) {
	trust, err := requireDefenseAuthorityEvidenceTrustV01(trusts)
	if err != nil {
		return DefenseValidationObservationV02{}, fmt.Errorf("authority observation trust: %w", err)
	}
	control, err = bindDefenseAuthorityControlV01(control, trust)
	if err != nil {
		return DefenseValidationObservationV02{}, err
	}
	if execution.Case.ControlRef != control.ControlRef || !strings.EqualFold(execution.Case.ControlConfigurationHash, control.ConfigurationHash) {
		return DefenseValidationObservationV02{}, errors.New("authority execution does not match control configuration")
	}
	binding = normalizeDefenseAuthorityObservationBindingV01(binding)
	if binding.ControlRef != control.ControlRef || binding.CaseRef != execution.Case.CaseRef || !strings.EqualFold(binding.ExecutionHash, execution.Case.ExecutionHash) || binding.Chain != execution.Chain || binding.ChainID != execution.ChainID {
		return DefenseValidationObservationV02{}, errors.New("authority observation binding does not match execution")
	}
	if binding.ObservationCompletedOffsetMS < execution.Case.ObservationWindowMS {
		return DefenseValidationObservationV02{}, errors.New("authority observation window did not complete")
	}
	digest, err := DefenseAuthorityObservationBindingDigestV01(binding)
	if err != nil {
		return DefenseValidationObservationV02{}, err
	}
	if err := event.VerifyEd25519(control.CollectorRef, control.CollectorPublicKey); err != nil {
		return DefenseValidationObservationV02{}, fmt.Errorf("authenticate authority security evidence event: %w", err)
	}
	canonical, err := event.Canonical()
	if err != nil {
		return DefenseValidationObservationV02{}, err
	}
	if canonical.Producer != control.CollectorRef {
		return DefenseValidationObservationV02{}, errors.New("authority event producer is not the independent collector")
	}
	if canonical.Subject.Chain != binding.Chain || canonical.Subject.Type != DefenseValidationObservationSubjectTypeV02 || canonical.Subject.ID != execution.Case.CaseRef {
		return DefenseValidationObservationV02{}, errors.New("authority event subject does not match validation case")
	}
	if canonical.Window.ToUnixMS-canonical.Window.FromUnixMS < binding.ObservationCompletedOffsetMS {
		return DefenseValidationObservationV02{}, errors.New("authority event window is incomplete")
	}
	if !containsDefenseValidationDigestV02(canonical.SourceDigests, execution.ContainmentReceiptSHA256) || !containsDefenseValidationDigestV02(canonical.SourceDigests, execution.AuthorityBindingSHA256) {
		return DefenseValidationObservationV02{}, errors.New("authority event is not bound to containment and authority evidence")
	}
	findingID := DefenseValidationObservationFindingIDV02(control.ControlRef, execution.Case.CaseRef)
	matched := 0
	for _, finding := range canonical.Findings {
		if finding.ID != findingID || finding.Kind != DefenseValidationObservationFindingKindV02 {
			continue
		}
		matched++
		if finding.State != securityevidence.StateVerified || !strings.EqualFold(finding.EvidenceSHA256, digest) {
			return DefenseValidationObservationV02{}, errors.New("authority observation finding is not verified against binding")
		}
	}
	if matched != 1 {
		return DefenseValidationObservationV02{}, errors.New("exactly one canonical authority observation finding is required")
	}
	out := DefenseValidationObservationV02{
		ControlRef: control.ControlRef, CollectorRef: control.CollectorRef, CaseRef: execution.Case.CaseRef,
		Status: binding.Status, ObservationEvidenceRef: "security-evidence:event:" + strings.ToLower(event.EventSHA256),
		ObservationEvidenceHash:      defenseValidationHashRefV02(event.EventSHA256),
		AlertObservedOffsetMS:        cloneDefenseValidationInt64V02(binding.AlertObservedOffsetMS),
		ObservationCompletedOffsetMS: binding.ObservationCompletedOffsetMS, EvidenceState: DefenseValidationEvidenceVerifiedV02,
	}
	if binding.Status == DefenseValidationObservationAlertedV02 {
		out.AlertEvidenceRef = "security-evidence:finding:" + findingID
		out.AlertEvidenceHash = defenseValidationHashRefV02(digest)
	}
	return out, nil
}

func bindDefenseAuthorityControlV01(control DefenseValidationControlV02, trust DefenseAuthorityEvidenceTrustV01) (DefenseValidationControlV02, error) {
	control.ControlRef = strings.TrimSpace(control.ControlRef)
	control.AdapterVersion = strings.TrimSpace(control.AdapterVersion)
	control.ConfigurationHash = strings.ToLower(strings.TrimSpace(control.ConfigurationHash))
	control.CollectorRef = strings.TrimSpace(control.CollectorRef)
	control.CollectorPublicKey = strings.TrimSpace(control.CollectorPublicKey)
	expected, err := NewAuthorityIntegrityControlV01(control.ControlRef, control.CollectorRef, DefenseAuthorityIntegrityConfigV01{
		EvidenceTrust:                trust,
		CollectorPublicKey:           control.CollectorPublicKey,
		IndependentCollectorRequired: true,
	})
	if err != nil {
		return DefenseValidationControlV02{}, fmt.Errorf("validate authority control: %w", err)
	}
	if control.AdapterVersion != expected.AdapterVersion || !strings.EqualFold(control.ConfigurationHash, expected.ConfigurationHash) {
		return DefenseValidationControlV02{}, errors.New("authority evidence trust does not match control configuration")
	}
	return expected, nil
}

func bindDefenseAuthorityScenarioV01(in DefenseAuthorityExecutionAdapterInputV01, control DefenseValidationControlV02) (string, *int64, error) {
	if !defenseValidationScenarioHasCompleteContractV02(in.Scenario) {
		return "", nil, errors.New("authority scenario must retain the complete parsed contract")
	}
	digest, err := DefenseValidationScenarioDigestV02(in.Scenario)
	if err != nil {
		return "", nil, fmt.Errorf("validate authority scenario: %w", err)
	}
	if control.AdapterVersion != DefenseAuthorityExecutionAdapterVersionV01 || strings.TrimSpace(in.Scenario.ControlContract.ControlClass) != "state_transition_authority_integrity" {
		return "", nil, errors.New("scenario does not select the authority integrity control")
	}
	if !strings.EqualFold(strings.TrimSpace(in.Scenario.Chain), in.Binding.Evidence.Chain) {
		return "", nil, errors.New("authority scenario chain does not match execution evidence")
	}
	if !defenseAuthorityScenarioExecutionModeMatchesV01(in.Scenario.Environment.ExecutionMode, in.ExecutionMode) {
		return "", nil, errors.New("authority scenario execution mode does not match adapted execution")
	}
	matched := 0
	var detectionDeadline *int64
	for _, scenarioCase := range in.Scenario.Matrix.Cases {
		if strings.TrimSpace(scenarioCase.CaseRef) != in.CaseRef {
			continue
		}
		matched++
		if strings.TrimSpace(scenarioCase.CaseKind) != in.CaseKind || scenarioCase.ObservationWindowMS != in.ObservationWindowMS || !equalDefenseAuthorityInt64PointersV01(scenarioCase.ImpactDeadlineMS, in.ImpactOffsetMS) {
			return "", nil, errors.New("authority execution does not match its scenario case contract")
		}
		detectionDeadline = cloneDefenseValidationInt64V02(scenarioCase.ExpectedControlBehavior.LatestDetectionOffsetMS)
	}
	if matched != 1 {
		return "", nil, errors.New("authority execution case is not an exact scenario member")
	}
	return digest, detectionDeadline, nil
}

func defenseAuthorityScenarioExecutionModeMatchesV01(scenarioMode, executionMode string) bool {
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

func equalDefenseAuthorityInt64PointersV01(a, b *int64) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func bindDefenseAuthorityReceiptV01(evidence DefenseAuthorityBindingEvidenceV01, receipt executioncontainment.Receipt) error {
	if receipt.Input.ChainID != evidence.ChainID || receipt.Observation.ObservedChainID != evidence.ChainID {
		return errors.New("containment receipt chain does not match authority evidence")
	}
	if !strings.EqualFold(receipt.Input.ApprovedPayloadSHA256, evidence.CallPayloadSHA256) || !strings.EqualFold(receipt.Input.CandidatePayloadSHA256, evidence.CallPayloadSHA256) {
		return errors.New("containment receipt payload does not match authority evidence")
	}
	if !strings.EqualFold(receipt.Observation.PreStateSHA256, evidence.PreStateSHA256) || !strings.EqualFold(receipt.Observation.PostStateSHA256, evidence.PostStateSHA256) || !strings.EqualFold(receipt.Observation.EffectSetSHA256, evidence.DebitEffectSHA256) {
		return errors.New("containment receipt state or effect does not match authority evidence")
	}
	return nil
}

func validateDefenseAuthorityCaseSemanticsV01(caseKind string, binding DefenseAuthorityBindingResultV01, receipt executioncontainment.Receipt) error {
	switch caseKind {
	case DefenseValidationCaseAttackV02:
		if binding.Preserved {
			return errors.New("authority attack case requires a failed authority binding")
		}
		if receipt.Decision != executioncontainment.DecisionContain || len(receipt.Reasons) != 2 ||
			!containsDefenseAuthorityContainmentReasonV01(receipt.Reasons, executioncontainment.ReasonAuthorityChanged) ||
			!containsDefenseAuthorityContainmentReasonV01(receipt.Reasons, executioncontainment.ReasonInvariantFailed) {
			return errors.New("authority attack requires containment for only authority-changed and invariant-failed reasons")
		}
	case DefenseValidationCaseBenignV02:
		if !binding.Preserved {
			return errors.New("authority benign case requires a preserved authority binding")
		}
		if receipt.Decision != executioncontainment.DecisionRelease || len(receipt.Reasons) != 0 {
			return errors.New("authority benign case requires an unqualified release receipt")
		}
	default:
		return fmt.Errorf("unsupported authority case kind %q", caseKind)
	}
	return nil
}

func containsDefenseAuthorityContainmentReasonV01(values []executioncontainment.ReasonCode, wanted executioncontainment.ReasonCode) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func normalizeDefenseAuthorityBindingEvidenceV01(e DefenseAuthorityBindingEvidenceV01) DefenseAuthorityBindingEvidenceV01 {
	if e.Version == "" {
		e.Version = DefenseAuthorityBindingVersionV01
	}
	e.Version = strings.TrimSpace(e.Version)
	e.EvidenceState = strings.ToLower(strings.TrimSpace(e.EvidenceState))
	e.Chain = strings.ToLower(strings.TrimSpace(e.Chain))
	e.CallerPrincipal = strings.TrimSpace(e.CallerPrincipal)
	e.DeclaredSourceAccount = strings.TrimSpace(e.DeclaredSourceAccount)
	e.RequestedOperation = strings.ToLower(strings.TrimSpace(e.RequestedOperation))
	e.RequestedAsset = strings.TrimSpace(e.RequestedAsset)
	e.AuthorizedPrincipal = strings.TrimSpace(e.AuthorizedPrincipal)
	e.AuthorizedSourceAccount = strings.TrimSpace(e.AuthorizedSourceAccount)
	e.AuthorizedOperation = strings.ToLower(strings.TrimSpace(e.AuthorizedOperation))
	e.AuthorizedAsset = strings.TrimSpace(e.AuthorizedAsset)
	e.CallPayloadSHA256 = strings.ToLower(strings.TrimSpace(e.CallPayloadSHA256))
	e.PrincipalEvidenceSHA256 = strings.ToLower(strings.TrimSpace(e.PrincipalEvidenceSHA256))
	e.AuthorizationEvidenceSHA256 = strings.ToLower(strings.TrimSpace(e.AuthorizationEvidenceSHA256))
	e.PreStateSHA256 = strings.ToLower(strings.TrimSpace(e.PreStateSHA256))
	e.PostStateSHA256 = strings.ToLower(strings.TrimSpace(e.PostStateSHA256))
	e.DebitEffectSHA256 = strings.ToLower(strings.TrimSpace(e.DebitEffectSHA256))
	e.PrincipalEvidence = normalizeDefenseAuthorityEvidenceArtifactV01(e.PrincipalEvidence)
	e.AuthorizationEvidence = normalizeDefenseAuthorityEvidenceArtifactV01(e.AuthorizationEvidence)
	return e
}

func validateDefenseAuthorityBindingEvidenceV01(e DefenseAuthorityBindingEvidenceV01, trust DefenseAuthorityEvidenceTrustV01) error {
	if e.Version != DefenseAuthorityBindingVersionV01 {
		return errors.New("unsupported authority binding version")
	}
	if e.EvidenceState != DefenseValidationEvidenceVerifiedV02 {
		return errors.New("authority binding requires verified evidence")
	}
	if e.Chain == "" || e.ChainID == 0 || e.CallerPrincipal == "" || e.DeclaredSourceAccount == "" || e.RequestedOperation == "" || e.RequestedAsset == "" || e.AuthorizedPrincipal == "" || e.AuthorizedSourceAccount == "" || e.AuthorizedOperation == "" || e.AuthorizedAsset == "" {
		return errors.New("authority binding identity and scope are incomplete")
	}
	for name, value := range map[string]string{
		"call_payload":           e.CallPayloadSHA256,
		"principal_evidence":     e.PrincipalEvidenceSHA256,
		"authorization_evidence": e.AuthorizationEvidenceSHA256,
		"pre_state":              e.PreStateSHA256,
		"post_state":             e.PostStateSHA256,
		"debit_effect":           e.DebitEffectSHA256,
	} {
		if !validDefenseAuthoritySHA256V01(value) {
			return fmt.Errorf("authority binding %s digest is invalid", name)
		}
	}
	if err := verifyDefenseAuthorityEvidenceArtifactV01(e.PrincipalEvidence, DefenseAuthorityEvidencePrincipalV01, trust.PrincipalProducerRef, trust.PrincipalPublicKey, e.PrincipalEvidenceSHA256); err != nil {
		return fmt.Errorf("verify principal authority evidence: %w", err)
	}
	if err := verifyDefenseAuthorityEvidenceArtifactV01(e.AuthorizationEvidence, DefenseAuthorityEvidenceAuthorizationV01, trust.AuthorizationProducerRef, trust.AuthorizationPublicKey, e.AuthorizationEvidenceSHA256); err != nil {
		return fmt.Errorf("verify authorization authority evidence: %w", err)
	}
	if !defenseAuthorityArtifactMatchesEvidenceV01(e.PrincipalEvidence, e, false) {
		return errors.New("principal authority evidence is not bound to the declared execution")
	}
	if !defenseAuthorityArtifactMatchesEvidenceV01(e.AuthorizationEvidence, e, true) {
		return errors.New("authorization authority evidence is not bound to the authorized scope")
	}
	return nil
}

func requireDefenseAuthorityEvidenceTrustV01(values []DefenseAuthorityEvidenceTrustV01) (DefenseAuthorityEvidenceTrustV01, error) {
	if len(values) != 1 {
		return DefenseAuthorityEvidenceTrustV01{}, errors.New("exactly one external authority evidence trust policy is required")
	}
	trust := values[0]
	trust.PrincipalProducerRef = strings.TrimSpace(trust.PrincipalProducerRef)
	trust.PrincipalPublicKey = strings.TrimSpace(trust.PrincipalPublicKey)
	trust.AuthorizationProducerRef = strings.TrimSpace(trust.AuthorizationProducerRef)
	trust.AuthorizationPublicKey = strings.TrimSpace(trust.AuthorizationPublicKey)
	if trust.PrincipalProducerRef == "" || trust.AuthorizationProducerRef == "" || trust.PrincipalProducerRef == trust.AuthorizationProducerRef {
		return DefenseAuthorityEvidenceTrustV01{}, errors.New("distinct trusted authority evidence producers are required")
	}
	principalKey, err := decodeDefenseAuthorityBase64V01(trust.PrincipalPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return DefenseAuthorityEvidenceTrustV01{}, fmt.Errorf("principal trust key: %w", err)
	}
	authorizationKey, err := decodeDefenseAuthorityBase64V01(trust.AuthorizationPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return DefenseAuthorityEvidenceTrustV01{}, fmt.Errorf("authorization trust key: %w", err)
	}
	if string(principalKey) == string(authorizationKey) {
		return DefenseAuthorityEvidenceTrustV01{}, errors.New("principal and authorization evidence require distinct trust keys")
	}
	return trust, nil
}

func normalizeDefenseAuthorityEvidenceArtifactV01(artifact DefenseAuthorityEvidenceArtifactV01) DefenseAuthorityEvidenceArtifactV01 {
	if strings.TrimSpace(artifact.Version) == "" {
		artifact.Version = DefenseAuthorityEvidenceArtifactVersionV01
	}
	artifact.Version = strings.TrimSpace(artifact.Version)
	artifact.EvidenceState = strings.ToLower(strings.TrimSpace(artifact.EvidenceState))
	artifact.EvidenceKind = strings.ToLower(strings.TrimSpace(artifact.EvidenceKind))
	artifact.Producer = strings.TrimSpace(artifact.Producer)
	artifact.Chain = strings.ToLower(strings.TrimSpace(artifact.Chain))
	artifact.Principal = strings.TrimSpace(artifact.Principal)
	artifact.SourceAccount = strings.TrimSpace(artifact.SourceAccount)
	artifact.Operation = strings.ToLower(strings.TrimSpace(artifact.Operation))
	artifact.Asset = strings.TrimSpace(artifact.Asset)
	artifact.CallPayloadSHA256 = strings.ToLower(strings.TrimSpace(artifact.CallPayloadSHA256))
	artifact.PreStateSHA256 = strings.ToLower(strings.TrimSpace(artifact.PreStateSHA256))
	artifact.PostStateSHA256 = strings.ToLower(strings.TrimSpace(artifact.PostStateSHA256))
	artifact.DebitEffectSHA256 = strings.ToLower(strings.TrimSpace(artifact.DebitEffectSHA256))
	artifact.Signature = strings.TrimSpace(artifact.Signature)
	return artifact
}

func validateDefenseAuthorityEvidenceArtifactShapeV01(artifact DefenseAuthorityEvidenceArtifactV01, signatureRequired bool) error {
	if artifact.Version != DefenseAuthorityEvidenceArtifactVersionV01 || artifact.EvidenceState != DefenseValidationEvidenceVerifiedV02 {
		return errors.New("authority evidence artifact version or state is unsupported")
	}
	if artifact.EvidenceKind == "" || artifact.Producer == "" || artifact.Chain == "" || artifact.ChainID == 0 || artifact.Principal == "" || artifact.SourceAccount == "" || artifact.Operation == "" || artifact.Asset == "" {
		return errors.New("authority evidence artifact identity and scope are incomplete")
	}
	for name, value := range map[string]string{
		"call_payload": artifact.CallPayloadSHA256,
		"pre_state":    artifact.PreStateSHA256,
		"post_state":   artifact.PostStateSHA256,
		"debit_effect": artifact.DebitEffectSHA256,
	} {
		if !validDefenseAuthoritySHA256V01(value) {
			return fmt.Errorf("authority evidence artifact %s digest is invalid", name)
		}
	}
	if signatureRequired && artifact.Signature == "" {
		return errors.New("authority evidence artifact signature is required")
	}
	return nil
}

func defenseAuthorityEvidenceArtifactSigningBytesV01(artifact DefenseAuthorityEvidenceArtifactV01) ([]byte, error) {
	artifact = normalizeDefenseAuthorityEvidenceArtifactV01(artifact)
	artifact.Signature = ""
	if err := validateDefenseAuthorityEvidenceArtifactShapeV01(artifact, false); err != nil {
		return nil, err
	}
	return json.Marshal(artifact)
}

func verifyDefenseAuthorityEvidenceArtifactV01(artifact DefenseAuthorityEvidenceArtifactV01, expectedKind, expectedProducer, trustedPublicKey, expectedDigest string) error {
	artifact = normalizeDefenseAuthorityEvidenceArtifactV01(artifact)
	if err := validateDefenseAuthorityEvidenceArtifactShapeV01(artifact, true); err != nil {
		return err
	}
	if artifact.EvidenceKind != expectedKind || artifact.Producer != expectedProducer {
		return errors.New("authority evidence artifact kind or producer does not match trust policy")
	}
	publicKey, err := decodeDefenseAuthorityBase64V01(trustedPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return err
	}
	signature, err := decodeDefenseAuthorityBase64V01(artifact.Signature, ed25519.SignatureSize)
	if err != nil {
		return fmt.Errorf("decode artifact signature: %w", err)
	}
	payload, err := defenseAuthorityEvidenceArtifactSigningBytesV01(artifact)
	if err != nil {
		return err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return errors.New("authority evidence artifact signature did not verify against trusted key")
	}
	digest, err := defenseAuthorityCanonicalSHA256V01(artifact)
	if err != nil {
		return err
	}
	if !strings.EqualFold(digest, expectedDigest) {
		return errors.New("authority evidence artifact digest does not match binding")
	}
	return nil
}

func defenseAuthorityArtifactMatchesEvidenceV01(artifact DefenseAuthorityEvidenceArtifactV01, evidence DefenseAuthorityBindingEvidenceV01, authorized bool) bool {
	principal, source, operation, asset := evidence.CallerPrincipal, evidence.DeclaredSourceAccount, evidence.RequestedOperation, evidence.RequestedAsset
	if authorized {
		principal, source, operation, asset = evidence.AuthorizedPrincipal, evidence.AuthorizedSourceAccount, evidence.AuthorizedOperation, evidence.AuthorizedAsset
	}
	return artifact.Chain == evidence.Chain && artifact.ChainID == evidence.ChainID &&
		artifact.Principal == principal && artifact.SourceAccount == source && artifact.Operation == operation && artifact.Asset == asset &&
		strings.EqualFold(artifact.CallPayloadSHA256, evidence.CallPayloadSHA256) &&
		strings.EqualFold(artifact.PreStateSHA256, evidence.PreStateSHA256) && strings.EqualFold(artifact.PostStateSHA256, evidence.PostStateSHA256) &&
		strings.EqualFold(artifact.DebitEffectSHA256, evidence.DebitEffectSHA256)
}

func decodeDefenseAuthorityBase64V01(value string, size int) ([]byte, error) {
	value = strings.TrimSpace(value)
	decoded, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil || len(decoded) != size || base64.RawURLEncoding.EncodeToString(decoded) != value {
		return nil, errors.New("value is not canonical base64url with the required length")
	}
	return decoded, nil
}

func normalizeDefenseAuthorityObservationBindingV01(binding DefenseAuthorityObservationBindingV01) DefenseAuthorityObservationBindingV01 {
	if binding.Version == "" {
		binding.Version = DefenseAuthorityObservationBindingVersionV01
	}
	binding.Version = strings.TrimSpace(binding.Version)
	binding.Chain = strings.ToLower(strings.TrimSpace(binding.Chain))
	binding.ControlRef = strings.TrimSpace(binding.ControlRef)
	binding.CaseRef = strings.TrimSpace(binding.CaseRef)
	binding.Status = strings.TrimSpace(binding.Status)
	binding.ExecutionHash = strings.ToLower(strings.TrimSpace(binding.ExecutionHash))
	return binding
}

func validDefenseAuthoritySHA256V01(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) != sha256.Size*2 {
		return false
	}
	_, err := hex.DecodeString(value)
	return err == nil
}

func defenseAuthorityCanonicalSHA256V01(value any) (string, error) {
	encoded, err := json.Marshal(value)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

func equalDefenseAuthorityStringsV01(a, b []string) bool {
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
