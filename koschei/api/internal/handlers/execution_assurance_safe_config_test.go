package handlers

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"testing"
)

func TestSafeExecutionAssuranceTrustFromEnvRejectsMalformedPublicKey(t *testing.T) {
	t.Setenv("KOSCHEI_EXECUTION_ASSURANCE_TRUSTED_PRODUCER", "collector-a")
	t.Setenv("KOSCHEI_EXECUTION_ASSURANCE_TRUSTED_ED25519_PUBLIC_KEY", "not-a-key")

	if _, err := safeExecutionAssuranceTrustFromEnv(); err == nil {
		t.Fatal("malformed trusted Ed25519 public key was accepted")
	}
}

func TestSafeExecutionAssuranceTrustFromEnvRejectsPaddedBase64(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x42}, ed25519.SeedSize))
	padded := base64.URLEncoding.EncodeToString(privateKey.Public().(ed25519.PublicKey))
	t.Setenv("KOSCHEI_EXECUTION_ASSURANCE_TRUSTED_PRODUCER", "collector-a")
	t.Setenv("KOSCHEI_EXECUTION_ASSURANCE_TRUSTED_ED25519_PUBLIC_KEY", padded)

	if _, err := safeExecutionAssuranceTrustFromEnv(); err == nil {
		t.Fatal("non-canonical padded base64 trust key was accepted")
	}
}
