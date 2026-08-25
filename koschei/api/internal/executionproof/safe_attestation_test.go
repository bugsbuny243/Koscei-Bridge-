package executionproof

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"fmt"
	"testing"
	"time"

	"koschei/api/internal/securityevidence"
)

func TestVerifySafeExecutionAttestationV1AcceptsTrustedFreshBinding(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	trust := SafeExecutionAttestationTrustV1{
		Producer:      "collector-a",
		PublicKey:     base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
		MaxAge:        5 * time.Minute,
		MaxFutureSkew: 30 * time.Second,
	}
	binding := SafeExecutionAttestationBindingV1{
		ChainID:              1,
		Safe:                 "0x1111111111111111111111111111111111111111",
		SafeTxHash:           "0x" + repeatHexAttestation("aa", 32),
		ExecutionProofSHA256: repeatHexAttestation("bb", 32),
	}
	event := signedSafeExecutionAttestationEvent(t, binding, trust.Producer, privateKey, now.Add(-30*time.Second), now.Add(-time.Second))

	if reasons := VerifySafeExecutionAttestationV1(event, binding, trust, now); len(reasons) != 0 {
		t.Fatalf("trusted fresh attestation blocked: %v", reasons)
	}
}

func TestVerifySafeExecutionAttestationV1RejectsUntrustedSigner(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	trustedKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	attackerKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x24}, ed25519.SeedSize))
	trust := SafeExecutionAttestationTrustV1{
		Producer:      "collector-a",
		PublicKey:     base64.RawURLEncoding.EncodeToString(trustedKey.Public().(ed25519.PublicKey)),
		MaxAge:        5 * time.Minute,
		MaxFutureSkew: 30 * time.Second,
	}
	binding := SafeExecutionAttestationBindingV1{
		ChainID:              1,
		Safe:                 "0x1111111111111111111111111111111111111111",
		SafeTxHash:           "0x" + repeatHexAttestation("aa", 32),
		ExecutionProofSHA256: repeatHexAttestation("bb", 32),
	}
	event := signedSafeExecutionAttestationEvent(t, binding, trust.Producer, attackerKey, now.Add(-30*time.Second), now.Add(-time.Second))

	reasons := VerifySafeExecutionAttestationV1(event, binding, trust, now)
	if len(reasons) != 1 || reasons[0] != ReasonUntrustedAttestation {
		t.Fatalf("untrusted signer did not fail closed: %v", reasons)
	}
}

func TestVerifySafeExecutionAttestationV1RejectsTrustedSignerBindingSubstitution(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	trust := SafeExecutionAttestationTrustV1{
		Producer:      "collector-a",
		PublicKey:     base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
		MaxAge:        5 * time.Minute,
		MaxFutureSkew: 30 * time.Second,
	}
	approvedBinding := SafeExecutionAttestationBindingV1{
		ChainID:              1,
		Safe:                 "0x1111111111111111111111111111111111111111",
		SafeTxHash:           "0x" + repeatHexAttestation("aa", 32),
		ExecutionProofSHA256: repeatHexAttestation("bb", 32),
	}
	event := signedSafeExecutionAttestationEvent(t, approvedBinding, trust.Producer, privateKey, now.Add(-30*time.Second), now.Add(-time.Second))

	substitutedBinding := approvedBinding
	substitutedBinding.SafeTxHash = "0x" + repeatHexAttestation("cc", 32)
	reasons := VerifySafeExecutionAttestationV1(event, substitutedBinding, trust, now)
	if len(reasons) != 1 || reasons[0] != ReasonUntrustedAttestation {
		t.Fatalf("trusted signer binding substitution did not fail closed: %v", reasons)
	}
}

func TestVerifySafeExecutionAttestationV1RejectsStaleBinding(t *testing.T) {
	now := time.Unix(1_800_000_000, 0).UTC()
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	trust := SafeExecutionAttestationTrustV1{
		Producer:      "collector-a",
		PublicKey:     base64.RawURLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey)),
		MaxAge:        5 * time.Minute,
		MaxFutureSkew: 30 * time.Second,
	}
	binding := SafeExecutionAttestationBindingV1{
		ChainID:              1,
		Safe:                 "0x1111111111111111111111111111111111111111",
		SafeTxHash:           "0x" + repeatHexAttestation("aa", 32),
		ExecutionProofSHA256: repeatHexAttestation("bb", 32),
	}
	event := signedSafeExecutionAttestationEvent(t, binding, trust.Producer, privateKey, now.Add(-7*time.Minute), now.Add(-6*time.Minute))

	reasons := VerifySafeExecutionAttestationV1(event, binding, trust, now)
	if len(reasons) != 1 || reasons[0] != ReasonStaleAttestation {
		t.Fatalf("stale attestation did not fail closed: %v", reasons)
	}
}

func signedSafeExecutionAttestationEvent(t *testing.T, binding SafeExecutionAttestationBindingV1, producer string, privateKey ed25519.PrivateKey, from, to time.Time) securityevidence.Event {
	t.Helper()
	digest, err := SafeExecutionAttestationBindingDigestV1(binding)
	if err != nil {
		t.Fatal(err)
	}
	canonical, err := binding.Canonical()
	if err != nil {
		t.Fatal(err)
	}
	event, err := (securityevidence.Event{
		Producer: producer,
		Subject: securityevidence.Subject{
			Chain: fmt.Sprintf("eip155:%d", canonical.ChainID),
			Type:  SafeExecutionAttestationSubjectTypeV1,
			ID:    canonical.SafeTxHash,
		},
		Window: securityevidence.ObservationWindow{
			FromUnixMS: from.UnixMilli(),
			ToUnixMS:   to.UnixMilli(),
		},
		SourceDigests: []string{canonical.ExecutionProofSHA256},
		Findings: []securityevidence.Finding{{
			ID:             SafeExecutionAttestationFindingIDV1,
			Kind:           SafeExecutionAttestationFindingKindV1,
			State:          securityevidence.StateVerified,
			EvidenceSHA256: digest,
		}},
	}).SignEd25519(privateKey)
	if err != nil {
		t.Fatal(err)
	}
	return event
}

func repeatHexAttestation(pair string, count int) string {
	var out bytes.Buffer
	for i := 0; i < count; i++ {
		out.WriteString(pair)
	}
	return out.String()
}
