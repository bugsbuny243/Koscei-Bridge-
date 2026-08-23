package defense

import (
	"crypto/sha256"
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

	DefenseAuthorityReasonPrincipalMismatchV01 = "principal_mismatch"
	DefenseAuthorityReasonSourceMismatchV01    = "source_account_mismatch"
	DefenseAuthorityReasonOperationMismatchV01 = "operation_mismatch"
	DefenseAuthorityReasonAssetMismatchV01     = "asset_mismatch"
)

type DefenseAuthorityBindingEvidenceV01 struct {
	Version                    string `json:"version"`
	EvidenceState              string `json:"evidence_state"`
	CallerPrincipal            string `json:"caller_principal"`
	DeclaredSourceAccount      string `json:"declared_source_account"`
	RequestedOperation         string `json:"requested_operation"`
	RequestedAsset             string `json:"requested_asset"`
	AuthorizedPrincipal        string `json:"authorized_principal"`
	AuthorizedSourceAccount    string `json:"authorized_source_account"`
	AuthorizedOperation        string `json:"authorized_operation"`
	AuthorizedAsset            string `json:"authorized_asset"`
	CallPayloadSHA256          string `json:"call_payload_sha256"`
	PrincipalEvidenceSHA256    string `json:"principal_evidence_sha256"`
	AuthorizationEvidenceSHA256 string `json:"authorization_evidence_sha256"`
	PreStateSHA256             string `json:"pre_state_sha256"`
	PostStateSHA256            string `json:"post_state_sha256"`
	DebitEffectSHA256          string `json:"debit_effect_sha256"`
}

type DefenseAuthorityBindingResultV01 struct {
	Version       string                              `json:"version"`
	Evidence      DefenseAuthorityBindingEvidenceV01 `json:"evidence"`
	Preserved     bool                                `json:"preserved"`
	Reasons       []string                            `json:"reasons"`
	BindingSHA256 string                              `json:"binding_sha256"`
}

type DefenseAuthorityIntegrityConfigV01 struct {
	SchemaVersion                string `json:"schema_version"`
	AuthorityBindingVersion      string `json:"authority_binding_version"`
	ExecutionContainmentVersion  string `json:"execution_containment_version"`
	IndependentCollectorRequired bool   `json:"independent_collector_required"`
	MainnetSubmissionAllowed     bool   `json:"mainnet_submission_allowed"`
	ProductionWiringClaim        bool   `json:"production_wiring_claim"`
}

type DefenseAuthorityExecutionAdapterInputV01 struct {
	CaseRef                string
	CaseKind               string
	TechniqueID            string
	ExecutionMode          string
	ImpactOffsetMS         *int64
	ObservationWindowMS    int64
	MainnetTransactionSent bool
	Binding                DefenseAuthorityBindingResultV01
	ContainmentReceipt     executioncontainment.Receipt
}

type DefenseAuthorityExecutionEvidenceV01 struct {
	Case                     DefenseValidationCaseV02
	ContainmentDecision      executioncontainment.Decision
	ContainmentReceiptSHA256 string
	AuthorityBindingSHA256   string
	ControlSignaled          bool
}

type DefenseAuthorityObservationBindingV01 struct {
	Version                      string `json:"version"`
	Chain                        string `json:"chain"`
	ControlRef                   string `json:"control_ref"`
	CaseRef                      string `json:"case_ref"`
	Status                       string `json:"status"`
	ExecutionHash                string `json:"execution_hash"`
	AlertObservedOffsetMS        *int64 `json:"alert_observed_offset_ms,omitempty"`
	ObservationCompletedOffsetMS int64  `json:"observation_completed_offset_ms"`
}

func EvaluateDefenseAuthorityBindingV01(e DefenseAuthorityBindingEvidenceV01) (DefenseAuthorityBindingResultV01, error) {
	e = normalizeDefenseAuthorityBindingEvidenceV01(e)
	if err := validateDefenseAuthorityBindingEvidenceV01(e); err != nil {
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
		Version:   DefenseAuthorityBindingVersionV01,
		Evidence:  e,
		Preserved: len(reasons) == 0,
		Reasons:   reasons,
	}
	digest, err := defenseAuthorityCanonicalSHA256V01(struct {
		Version   string                              `json:"version"`
		Evidence  DefenseAuthorityBindingEvidenceV01 `json:"evidence"`
		Preserved bool                                `json:"preserved"`
		Reasons   []string                            `json:"reasons"`
	}{out.Version, out.Evidence, out.Preserved, out.Reasons})
	if err != nil {
		return DefenseAuthorityBindingResultV01{}, err
	}
	out.BindingSHA256 = digest
	return out, nil
}

func VerifyDefenseAuthorityBindingV01(result DefenseAuthorityBindingResultV01) bool {
	if result.Version != DefenseAuthorityBindingVersionV01 || !validDefenseAuthoritySHA256V01(result.BindingSHA256) {
		return false
	}
	recomputed, err := EvaluateDefenseAuthorityBindingV01(result.Evidence)
	if err != nil {
		return false
	}
	return recomputed.Preserved == result.Preserved &&
		equalDefenseAuthorityStringsV01(recomputed.Reasons, result.Reasons) &&
		strings.EqualFold(recomputed.BindingSHA256, result.BindingSHA256)
}

func ApplyDefenseAuthorityBindingToContainmentV01(observation executioncontainment.Observation, result DefenseAuthorityBindingResultV01) (executioncontainment.Observation, error) {
	if !VerifyDefenseAuthorityBindingV01(result) {
		return executioncontainment.Observation{}, errors.New("authority binding evidence failed deterministic verification")
	}
	observation.AuthorityPreserved = result.Preserved
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
	return DefenseValidationControlV02{ControlRef: controlRef, AdapterVersion: DefenseAuthorityExecutionAdapterVersionV01, ConfigurationHash: digest, CollectorRef: collectorRef}, nil
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
	if !VerifyDefenseAuthorityBindingV01(in.Binding) {
		return DefenseAuthorityExecutionEvidenceV01{}, errors.New("authority binding failed deterministic recomputation")
	}
	if !executioncontainment.Verify(in.ContainmentReceipt) || !in.ContainmentReceipt.Observation.BackendAvailable {
		return DefenseAuthorityExecutionEvidenceV01{}, errors.New("containment receipt is unavailable or invalid")
	}
	if in.ContainmentReceipt.Observation.AuthorityPreserved != in.Binding.Preserved {
		return DefenseAuthorityExecutionEvidenceV01{}, errors.New("containment authority observation contradicts binding result")
	}
	if !in.Binding.Preserved && in.ContainmentReceipt.Decision != executioncontainment.DecisionContain {
		return DefenseAuthorityExecutionEvidenceV01{}, errors.New("authority mismatch did not fail closed")
	}

	executionHash, err := defenseAuthorityCanonicalSHA256V01(struct {
		AdapterVersion           string                        `json:"adapter_version"`
		CaseRef                  string                        `json:"case_ref"`
		CaseKind                 string                        `json:"case_kind"`
		TechniqueID              string                        `json:"technique_id"`
		ExecutionMode            string                        `json:"execution_mode"`
		AuthorityBindingSHA256   string                        `json:"authority_binding_sha256"`
		ContainmentReceiptSHA256 string                        `json:"containment_receipt_sha256"`
		ContainmentDecision      executioncontainment.Decision `json:"containment_decision"`
		PreStateSHA256           string                        `json:"pre_state_sha256"`
		PostStateSHA256          string                        `json:"post_state_sha256"`
		ObservationWindowMS      int64                         `json:"observation_window_ms"`
	}{
		DefenseAuthorityExecutionAdapterVersionV01, in.CaseRef, in.CaseKind, in.TechniqueID, in.ExecutionMode,
		strings.ToLower(in.Binding.BindingSHA256), strings.ToLower(in.ContainmentReceipt.ReceiptSHA256), in.ContainmentReceipt.Decision,
		strings.ToLower(in.ContainmentReceipt.Observation.PreStateSHA256), strings.ToLower(in.ContainmentReceipt.Observation.PostStateSHA256), in.ObservationWindowMS,
	})
	if err != nil {
		return DefenseAuthorityExecutionEvidenceV01{}, err
	}
	validationCase := DefenseValidationCaseV02{
		CaseRef: in.CaseRef, CaseKind: in.CaseKind, TechniqueID: in.TechniqueID, ExecutionMode: in.ExecutionMode,
		ExecutionRef: "defense-authority-execution:" + executionHash, ExecutionHash: executionHash,
		PreStateHash: defenseValidationHashRefV02(in.ContainmentReceipt.Observation.PreStateSHA256),
		PostStateHash: defenseValidationHashRefV02(in.ContainmentReceipt.Observation.PostStateSHA256),
		EvidenceState: DefenseValidationEvidenceVerifiedV02, ImpactOffsetMS: cloneDefenseValidationInt64V02(in.ImpactOffsetMS),
		ObservationWindowMS: in.ObservationWindowMS, MainnetTransactionSent: false,
	}
	return DefenseAuthorityExecutionEvidenceV01{
		Case: validationCase, ContainmentDecision: in.ContainmentReceipt.Decision,
		ContainmentReceiptSHA256: strings.ToLower(in.ContainmentReceipt.ReceiptSHA256),
		AuthorityBindingSHA256: strings.ToLower(in.Binding.BindingSHA256),
		ControlSignaled: in.ContainmentReceipt.Decision != executioncontainment.DecisionRelease,
	}, nil
}

func DefenseAuthorityObservationBindingDigestV01(binding DefenseAuthorityObservationBindingV01) (string, error) {
	binding = normalizeDefenseAuthorityObservationBindingV01(binding)
	if binding.Version != DefenseAuthorityObservationBindingVersionV01 || binding.Chain == "" || binding.ControlRef == "" || binding.CaseRef == "" || !validDefenseAuthoritySHA256V01(binding.ExecutionHash) {
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

func AdaptAuthoritySecurityEvidenceObservationV01(control DefenseValidationControlV02, execution DefenseAuthorityExecutionEvidenceV01, binding DefenseAuthorityObservationBindingV01, event securityevidence.Event) (DefenseValidationObservationV02, error) {
	if control.ControlRef == "" || control.CollectorRef == "" || control.ControlRef == control.CollectorRef {
		return DefenseValidationObservationV02{}, errors.New("independent collector identity is required")
	}
	binding = normalizeDefenseAuthorityObservationBindingV01(binding)
	if binding.ControlRef != control.ControlRef || binding.CaseRef != execution.Case.CaseRef || !strings.EqualFold(binding.ExecutionHash, execution.Case.ExecutionHash) {
		return DefenseValidationObservationV02{}, errors.New("authority observation binding does not match execution")
	}
	expected := DefenseValidationObservationNoAlertV02
	if execution.ControlSignaled {
		expected = DefenseValidationObservationAlertedV02
	}
	if binding.Status != expected {
		return DefenseValidationObservationV02{}, errors.New("authority observation contradicts verified control decision")
	}
	if binding.ObservationCompletedOffsetMS < execution.Case.ObservationWindowMS {
		return DefenseValidationObservationV02{}, errors.New("authority observation window did not complete")
	}
	digest, err := DefenseAuthorityObservationBindingDigestV01(binding)
	if err != nil {
		return DefenseValidationObservationV02{}, err
	}
	if err := event.Verify(); err != nil {
		return DefenseValidationObservationV02{}, fmt.Errorf("verify authority security evidence event: %w", err)
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
		ObservationEvidenceHash: defenseValidationHashRefV02(event.EventSHA256),
		AlertObservedOffsetMS: cloneDefenseValidationInt64V02(binding.AlertObservedOffsetMS),
		ObservationCompletedOffsetMS: binding.ObservationCompletedOffsetMS, EvidenceState: DefenseValidationEvidenceVerifiedV02,
	}
	if binding.Status == DefenseValidationObservationAlertedV02 {
		out.AlertEvidenceRef = "security-evidence:finding:" + findingID
		out.AlertEvidenceHash = defenseValidationHashRefV02(digest)
	}
	return out, nil
}

func normalizeDefenseAuthorityBindingEvidenceV01(e DefenseAuthorityBindingEvidenceV01) DefenseAuthorityBindingEvidenceV01 {
	if e.Version == "" {
		e.Version = DefenseAuthorityBindingVersionV01
	}
	e.Version = strings.TrimSpace(e.Version)
	e.EvidenceState = strings.ToLower(strings.TrimSpace(e.EvidenceState))
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
	return e
}

func validateDefenseAuthorityBindingEvidenceV01(e DefenseAuthorityBindingEvidenceV01) error {
	if e.Version != DefenseAuthorityBindingVersionV01 {
		return errors.New("unsupported authority binding version")
	}
	if e.EvidenceState != DefenseValidationEvidenceVerifiedV02 {
		return errors.New("authority binding requires verified evidence")
	}
	if e.CallerPrincipal == "" || e.DeclaredSourceAccount == "" || e.RequestedOperation == "" || e.RequestedAsset == "" || e.AuthorizedPrincipal == "" || e.AuthorizedSourceAccount == "" || e.AuthorizedOperation == "" || e.AuthorizedAsset == "" {
		return errors.New("authority binding identity and scope are incomplete")
	}
	for name, value := range map[string]string{
		"call_payload": e.CallPayloadSHA256,
		"principal_evidence": e.PrincipalEvidenceSHA256,
		"authorization_evidence": e.AuthorizationEvidenceSHA256,
		"pre_state": e.PreStateSHA256,
		"post_state": e.PostStateSHA256,
		"debit_effect": e.DebitEffectSHA256,
	} {
		if !validDefenseAuthoritySHA256V01(value) {
			return fmt.Errorf("authority binding %s digest is invalid", name)
		}
	}
	return nil
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
