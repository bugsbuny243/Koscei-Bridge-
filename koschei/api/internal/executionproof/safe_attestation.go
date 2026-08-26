package executionproof

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"koschei/api/internal/securityevidence"
)

const (
	SafeExecutionAttestationVersionV1     = "koschei.safe-execution-attestation/v1"
	SafeExecutionAttestationSubjectTypeV1 = "safe_execution_assurance"
	SafeExecutionAttestationFindingIDV1   = "safe-execution-binding"
	SafeExecutionAttestationFindingKindV1 = "safe_execution_binding"

	ReasonUntrustedAttestation ReasonCode = "EP-010-UNTRUSTED-ATTESTATION"
	ReasonStaleAttestation     ReasonCode = "EP-011-STALE-ATTESTATION"
)

type SafeExecutionAttestationBindingV1 struct {
	Version                      string `json:"version"`
	ChainID                      uint64 `json:"chain_id"`
	Safe                         string `json:"safe"`
	SafeTxHash                   string `json:"safe_tx_hash"`
	ExecutionProofEnvelopeSHA256 string `json:"execution_proof_envelope_sha256"`
}

type SafeExecutionAttestationTrustV1 struct {
	Producer      string
	PublicKey     string
	MaxAge        time.Duration
	MaxFutureSkew time.Duration
}

func (b SafeExecutionAttestationBindingV1) Canonical() (SafeExecutionAttestationBindingV1, error) {
	out := b
	out.Version = strings.TrimSpace(out.Version)
	if out.Version == "" {
		out.Version = SafeExecutionAttestationVersionV1
	}
	if out.Version != SafeExecutionAttestationVersionV1 {
		return SafeExecutionAttestationBindingV1{}, fmt.Errorf("unsupported Safe execution attestation version %q", out.Version)
	}
	if out.ChainID == 0 {
		return SafeExecutionAttestationBindingV1{}, errors.New("Safe execution attestation chain_id is required")
	}
	canonicalSafe, err := canonicalHexAddress20(out.Safe)
	if err != nil {
		return SafeExecutionAttestationBindingV1{}, errors.New("Safe execution attestation safe address is invalid")
	}
	out.Safe = canonicalSafe
	out.SafeTxHash = strings.ToLower(strings.TrimSpace(out.SafeTxHash))
	if !validHex32(out.SafeTxHash) {
		return SafeExecutionAttestationBindingV1{}, errors.New("Safe execution attestation safeTxHash is invalid")
	}
	out.ExecutionProofEnvelopeSHA256 = strings.ToLower(strings.TrimSpace(out.ExecutionProofEnvelopeSHA256))
	if !validSHA256(out.ExecutionProofEnvelopeSHA256) {
		return SafeExecutionAttestationBindingV1{}, errors.New("Safe execution attestation proof envelope digest is invalid")
	}
	return out, nil
}

func canonicalHexAddress20(value string) (string, error) {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "0x") || strings.HasPrefix(value, "0X") {
		value = value[2:]
	}
	if len(value) != 40 {
		return "", errors.New("address must contain exactly 20 bytes")
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != 20 {
		return "", errors.New("address must be hexadecimal")
	}
	return "0x" + strings.ToLower(value), nil
}

func SafeExecutionAttestationBindingDigestV1(binding SafeExecutionAttestationBindingV1) (string, error) {
	canonical, err := binding.Canonical()
	if err != nil {
		return "", err
	}
	encoded, err := json.Marshal(canonical)
	if err != nil {
		return "", fmt.Errorf("marshal Safe execution attestation binding: %w", err)
	}
	sum := sha256.Sum256(encoded)
	return hex.EncodeToString(sum[:]), nil
}

// VerifySafeExecutionAttestationV1 authenticates the independently produced
// evidence event against trust material supplied by the server, never by the
// request. The signed event must bind the exact recomputed Execution Proof
// envelope digest and Safe transaction hash, and its complete observation
// window must still be fresh.
func VerifySafeExecutionAttestationV1(event securityevidence.Event, binding SafeExecutionAttestationBindingV1, trust SafeExecutionAttestationTrustV1, now time.Time) []ReasonCode {
	trust.Producer = strings.TrimSpace(trust.Producer)
	trust.PublicKey = strings.TrimSpace(trust.PublicKey)
	if trust.Producer == "" || trust.PublicKey == "" || trust.MaxAge <= 0 || trust.MaxFutureSkew < 0 {
		return []ReasonCode{ReasonUntrustedAttestation}
	}
	canonicalBinding, err := binding.Canonical()
	if err != nil {
		return []ReasonCode{ReasonUntrustedAttestation}
	}
	bindingDigest, err := SafeExecutionAttestationBindingDigestV1(canonicalBinding)
	if err != nil {
		return []ReasonCode{ReasonUntrustedAttestation}
	}
	if err := event.VerifyEd25519(trust.Producer, trust.PublicKey); err != nil {
		return []ReasonCode{ReasonUntrustedAttestation}
	}
	canonicalEvent, err := event.Canonical()
	if err != nil {
		return []ReasonCode{ReasonUntrustedAttestation}
	}

	expectedChain := fmt.Sprintf("eip155:%d", canonicalBinding.ChainID)
	if canonicalEvent.Subject.Chain != expectedChain ||
		canonicalEvent.Subject.Type != SafeExecutionAttestationSubjectTypeV1 ||
		!strings.EqualFold(canonicalEvent.Subject.ID, canonicalBinding.SafeTxHash) ||
		len(canonicalEvent.SourceDigests) != 1 ||
		!strings.EqualFold(canonicalEvent.SourceDigests[0], canonicalBinding.ExecutionProofEnvelopeSHA256) ||
		!hasVerifiedSafeExecutionBindingV1(canonicalEvent.Findings, bindingDigest) {
		return []ReasonCode{ReasonUntrustedAttestation}
	}

	nowMS := now.UTC().UnixMilli()
	maxFutureMS := trust.MaxFutureSkew.Milliseconds()
	maxAgeMS := trust.MaxAge.Milliseconds()
	if canonicalEvent.Window.ToUnixMS > nowMS+maxFutureMS || nowMS-canonicalEvent.Window.FromUnixMS > maxAgeMS {
		return []ReasonCode{ReasonStaleAttestation}
	}
	return nil
}

func hasVerifiedSafeExecutionBindingV1(findings []securityevidence.Finding, bindingDigest string) bool {
	for _, finding := range findings {
		if finding.ID == SafeExecutionAttestationFindingIDV1 &&
			finding.Kind == SafeExecutionAttestationFindingKindV1 &&
			finding.State == securityevidence.StateVerified &&
			strings.EqualFold(finding.EvidenceSHA256, bindingDigest) {
			return true
		}
	}
	return false
}
