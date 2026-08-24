package defense

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"koschei/api/internal/executioncontainment"
)

const (
	DefenseAuthorityNativeExecutionAttestationVersionV01 = "koschei-defense-authority-native-execution-attestation/v0.1.0"
	DefenseAuthorityNativeBackendCosmosEVMV01            = "concrete_isolated_cosmos_evm"
)

// DefenseAuthorityNativeExecutionAttestationV01 is emitted by the pinned
// isolated Cosmos-EVM runner. Its signer is an external trust anchor, distinct
// from the authority-artifact producers, the control, and the observer.
type DefenseAuthorityNativeExecutionAttestationV01 struct {
	Version                            string `json:"version"`
	EvidenceState                      string `json:"evidence_state"`
	Producer                           string `json:"producer"`
	BackendKind                        string `json:"backend_kind"`
	ExecutionMode                      string `json:"execution_mode"`
	Chain                              string `json:"chain"`
	ChainID                            uint64 `json:"chain_id"`
	BlockNumber                        uint64 `json:"block_number"`
	BlockHash                          string `json:"block_hash"`
	RunnerSHA256                       string `json:"runner_sha256"`
	ModuleRoute                        string `json:"module_route"`
	NativeAuthorizationRouteReproduced bool   `json:"native_authorization_route_reproduced"`
	NativeAuthorizationTraceSHA256     string `json:"native_authorization_trace_sha256"`
	CallPayloadSHA256                  string `json:"call_payload_sha256"`
	PreStateSHA256                     string `json:"pre_state_sha256"`
	PostStateSHA256                    string `json:"post_state_sha256"`
	DebitEffectSHA256                  string `json:"debit_effect_sha256"`
	ContainmentReceiptSHA256           string `json:"containment_receipt_sha256"`
	NetworkAccessDuringExecution       bool   `json:"network_access_during_execution"`
	ProductionIdentityUsed             bool   `json:"production_identity_used"`
	MainnetTransactionSent             bool   `json:"mainnet_transaction_sent"`
	Signature                          string `json:"signature"`
}

type defenseAuthorityNativeExecutionAttestationUnsignedV01 struct {
	Version                            string `json:"version"`
	EvidenceState                      string `json:"evidence_state"`
	Producer                           string `json:"producer"`
	BackendKind                        string `json:"backend_kind"`
	ExecutionMode                      string `json:"execution_mode"`
	Chain                              string `json:"chain"`
	ChainID                            uint64 `json:"chain_id"`
	BlockNumber                        uint64 `json:"block_number"`
	BlockHash                          string `json:"block_hash"`
	RunnerSHA256                       string `json:"runner_sha256"`
	ModuleRoute                        string `json:"module_route"`
	NativeAuthorizationRouteReproduced bool   `json:"native_authorization_route_reproduced"`
	NativeAuthorizationTraceSHA256     string `json:"native_authorization_trace_sha256"`
	CallPayloadSHA256                  string `json:"call_payload_sha256"`
	PreStateSHA256                     string `json:"pre_state_sha256"`
	PostStateSHA256                    string `json:"post_state_sha256"`
	DebitEffectSHA256                  string `json:"debit_effect_sha256"`
	ContainmentReceiptSHA256           string `json:"containment_receipt_sha256"`
	NetworkAccessDuringExecution       bool   `json:"network_access_during_execution"`
	ProductionIdentityUsed             bool   `json:"production_identity_used"`
	MainnetTransactionSent             bool   `json:"mainnet_transaction_sent"`
}

func (a DefenseAuthorityNativeExecutionAttestationV01) SignEd25519(privateKey ed25519.PrivateKey) (DefenseAuthorityNativeExecutionAttestationV01, error) {
	if len(privateKey) != ed25519.PrivateKeySize {
		return DefenseAuthorityNativeExecutionAttestationV01{}, errors.New("native execution attestation private key is invalid")
	}
	a = normalizeDefenseAuthorityNativeExecutionAttestationV01(a)
	if err := validateDefenseAuthorityNativeExecutionAttestationShapeV01(a); err != nil {
		return DefenseAuthorityNativeExecutionAttestationV01{}, err
	}
	payload, err := defenseAuthorityNativeExecutionAttestationSigningBytesV01(a)
	if err != nil {
		return DefenseAuthorityNativeExecutionAttestationV01{}, err
	}
	a.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return a, nil
}

func verifyDefenseAuthorityNativeExecutionAttestationV01(
	a DefenseAuthorityNativeExecutionAttestationV01,
	trust DefenseAuthorityEvidenceTrustV01,
	executionMode string,
	binding DefenseAuthorityBindingResultV01,
	receipt executioncontainment.Receipt,
) (string, error) {
	a = normalizeDefenseAuthorityNativeExecutionAttestationV01(a)
	if err := validateDefenseAuthorityNativeExecutionAttestationShapeV01(a); err != nil {
		return "", err
	}
	if a.Producer != trust.NativeRunnerProducerRef {
		return "", errors.New("native execution attestation producer is not trusted")
	}
	publicKey, err := decodeDefenseAuthorityBase64V01(trust.NativeRunnerPublicKey, ed25519.PublicKeySize)
	if err != nil {
		return "", fmt.Errorf("native runner trust key: %w", err)
	}
	signature, err := decodeDefenseAuthorityBase64V01(a.Signature, ed25519.SignatureSize)
	if err != nil {
		return "", fmt.Errorf("native execution attestation signature: %w", err)
	}
	payload, err := defenseAuthorityNativeExecutionAttestationSigningBytesV01(a)
	if err != nil {
		return "", err
	}
	if !ed25519.Verify(ed25519.PublicKey(publicKey), payload, signature) {
		return "", errors.New("native execution attestation signature is invalid")
	}
	evidence := binding.Evidence
	if a.ExecutionMode != strings.TrimSpace(executionMode) || a.Chain != evidence.Chain || a.ChainID != evidence.ChainID ||
		a.BlockNumber != receipt.Input.BlockNumber || !strings.EqualFold(a.BlockHash, receipt.Input.BlockHash) ||
		!strings.EqualFold(a.BlockHash, receipt.Observation.ObservedBlockHash) ||
		!strings.EqualFold(a.RunnerSHA256, receipt.Input.ApprovedRunnerSHA256) ||
		!strings.EqualFold(a.RunnerSHA256, receipt.Observation.ObservedRunnerSHA256) ||
		a.ModuleRoute != evidence.ModuleRoute || a.ModuleRoute != receipt.Input.Target ||
		!strings.EqualFold(a.CallPayloadSHA256, evidence.CallPayloadSHA256) ||
		!strings.EqualFold(a.CallPayloadSHA256, receipt.Input.ApprovedPayloadSHA256) ||
		!strings.EqualFold(a.CallPayloadSHA256, receipt.Input.CandidatePayloadSHA256) ||
		!strings.EqualFold(a.PreStateSHA256, evidence.PreStateSHA256) ||
		!strings.EqualFold(a.PreStateSHA256, receipt.Observation.PreStateSHA256) ||
		!strings.EqualFold(a.PostStateSHA256, evidence.PostStateSHA256) ||
		!strings.EqualFold(a.PostStateSHA256, receipt.Observation.PostStateSHA256) ||
		!strings.EqualFold(a.DebitEffectSHA256, evidence.DebitEffectSHA256) ||
		!strings.EqualFold(a.DebitEffectSHA256, receipt.Observation.EffectSetSHA256) ||
		!strings.EqualFold(a.ContainmentReceiptSHA256, receipt.ReceiptSHA256) {
		return "", errors.New("native execution attestation does not match authority execution evidence")
	}
	digest, err := defenseAuthorityCanonicalSHA256V01(a)
	if err != nil {
		return "", fmt.Errorf("hash native execution attestation: %w", err)
	}
	return digest, nil
}

func normalizeDefenseAuthorityNativeExecutionAttestationV01(a DefenseAuthorityNativeExecutionAttestationV01) DefenseAuthorityNativeExecutionAttestationV01 {
	if strings.TrimSpace(a.Version) == "" {
		a.Version = DefenseAuthorityNativeExecutionAttestationVersionV01
	}
	a.Version = strings.TrimSpace(a.Version)
	a.EvidenceState = strings.ToLower(strings.TrimSpace(a.EvidenceState))
	a.Producer = strings.TrimSpace(a.Producer)
	a.BackendKind = strings.ToLower(strings.TrimSpace(a.BackendKind))
	a.ExecutionMode = strings.ToLower(strings.TrimSpace(a.ExecutionMode))
	a.Chain = strings.ToLower(strings.TrimSpace(a.Chain))
	a.BlockHash = strings.ToLower(strings.TrimSpace(a.BlockHash))
	a.RunnerSHA256 = strings.ToLower(strings.TrimSpace(a.RunnerSHA256))
	a.ModuleRoute = strings.TrimSpace(a.ModuleRoute)
	a.NativeAuthorizationTraceSHA256 = strings.ToLower(strings.TrimSpace(a.NativeAuthorizationTraceSHA256))
	a.CallPayloadSHA256 = strings.ToLower(strings.TrimSpace(a.CallPayloadSHA256))
	a.PreStateSHA256 = strings.ToLower(strings.TrimSpace(a.PreStateSHA256))
	a.PostStateSHA256 = strings.ToLower(strings.TrimSpace(a.PostStateSHA256))
	a.DebitEffectSHA256 = strings.ToLower(strings.TrimSpace(a.DebitEffectSHA256))
	a.ContainmentReceiptSHA256 = strings.ToLower(strings.TrimSpace(a.ContainmentReceiptSHA256))
	a.Signature = strings.TrimSpace(a.Signature)
	return a
}

func validateDefenseAuthorityNativeExecutionAttestationShapeV01(a DefenseAuthorityNativeExecutionAttestationV01) error {
	if a.Version != DefenseAuthorityNativeExecutionAttestationVersionV01 || a.EvidenceState != DefenseValidationEvidenceVerifiedV02 {
		return errors.New("native execution attestation is not verified evidence")
	}
	if a.Producer == "" || a.BackendKind != DefenseAuthorityNativeBackendCosmosEVMV01 || a.ExecutionMode != DefenseValidationExecutionSandboxV02 ||
		a.Chain == "" || a.ChainID == 0 || a.BlockNumber == 0 || a.ModuleRoute == "" || !a.NativeAuthorizationRouteReproduced {
		return errors.New("native execution attestation does not satisfy the concrete Cosmos-EVM authorization-route gate")
	}
	if a.NetworkAccessDuringExecution || a.ProductionIdentityUsed || a.MainnetTransactionSent {
		return errors.New("native execution attestation violates the isolated safety boundary")
	}
	for name, value := range map[string]string{
		"block":                      a.BlockHash,
		"runner":                     a.RunnerSHA256,
		"native_authorization_trace": a.NativeAuthorizationTraceSHA256,
		"call_payload":               a.CallPayloadSHA256,
		"pre_state":                  a.PreStateSHA256,
		"post_state":                 a.PostStateSHA256,
		"debit_effect":               a.DebitEffectSHA256,
		"containment_receipt":        a.ContainmentReceiptSHA256,
	} {
		if !validDefenseAuthoritySHA256V01(value) {
			return fmt.Errorf("native execution attestation %s digest is invalid", name)
		}
	}
	return nil
}

func defenseAuthorityNativeExecutionAttestationSigningBytesV01(a DefenseAuthorityNativeExecutionAttestationV01) ([]byte, error) {
	a = normalizeDefenseAuthorityNativeExecutionAttestationV01(a)
	return json.Marshal(defenseAuthorityNativeExecutionAttestationUnsignedV01{
		Version:                            a.Version,
		EvidenceState:                      a.EvidenceState,
		Producer:                           a.Producer,
		BackendKind:                        a.BackendKind,
		ExecutionMode:                      a.ExecutionMode,
		Chain:                              a.Chain,
		ChainID:                            a.ChainID,
		BlockNumber:                        a.BlockNumber,
		BlockHash:                          a.BlockHash,
		RunnerSHA256:                       a.RunnerSHA256,
		ModuleRoute:                        a.ModuleRoute,
		NativeAuthorizationRouteReproduced: a.NativeAuthorizationRouteReproduced,
		NativeAuthorizationTraceSHA256:     a.NativeAuthorizationTraceSHA256,
		CallPayloadSHA256:                  a.CallPayloadSHA256,
		PreStateSHA256:                     a.PreStateSHA256,
		PostStateSHA256:                    a.PostStateSHA256,
		DebitEffectSHA256:                  a.DebitEffectSHA256,
		ContainmentReceiptSHA256:           a.ContainmentReceiptSHA256,
		NetworkAccessDuringExecution:       a.NetworkAccessDuringExecution,
		ProductionIdentityUsed:             a.ProductionIdentityUsed,
		MainnetTransactionSent:             a.MainnetTransactionSent,
	})
}
