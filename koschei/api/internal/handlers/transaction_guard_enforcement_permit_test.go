package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"
)

func TestTransactionGuardEnforcementPermitBindsTransactionAndTTL(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(i + 1)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	now := time.Date(2026, 8, 8, 2, 0, 0, 0, time.UTC)
	input := transactionGuardV2Request{Transaction: "fixture-transaction", Network: "solana-mainnet", Wallet: "Wallet111"}
	permit, err := signTransactionGuardEnforcementPermit(privateKey, "guard-v1", 90*time.Second, input, "req-1", transactionFirewallAssessment{Action: "allow"}, now)
	if err != nil {
		t.Fatal(err)
	}
	parts := strings.Split(permit.Token, ".")
	if len(parts) != 2 {
		t.Fatalf("token parts=%d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatal(err)
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatal(err)
	}
	if !ed25519.Verify(privateKey.Public().(ed25519.PublicKey), payload, signature) {
		t.Fatal("permit signature did not verify")
	}
	var claims transactionGuardEnforcementPermitClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatal(err)
	}
	if claims.TransactionFingerprint != transactionFingerprint(input.Transaction) || claims.RequestID != "req-1" || claims.KeyID != "guard-v1" {
		t.Fatalf("claims not bound: %#v", claims)
	}
	expires, _ := time.Parse(time.RFC3339Nano, claims.ExpiresAt)
	if expires.Sub(now) != 90*time.Second {
		t.Fatalf("ttl=%s", expires.Sub(now))
	}
}

func TestTransactionGuardEnforcementStateFailsClosedWhenRequiredSignerInvalid(t *testing.T) {
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "true")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "guard-v1")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", "not-a-key")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PERMIT_TTL_SECONDS", "90")
	state := buildTransactionGuardEnforcementState(transactionGuardV2Request{Transaction: "fixture", Network: "solana-mainnet"}, "req", transactionFirewallAssessment{Action: "allow"}, true, time.Now())
	if !state.Required || state.Issued || state.Status != "signer_invalid" {
		t.Fatalf("unexpected state: %#v", state)
	}
}

func TestTransactionGuardEnforcementStateNeverIssuesForWarn(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "true")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "guard-v1")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(seed))
	state := buildTransactionGuardEnforcementState(transactionGuardV2Request{Transaction: "fixture", Network: "solana-mainnet"}, "req", transactionFirewallAssessment{Action: "warn"}, true, time.Now())
	if state.Issued || state.Status != "not_eligible" {
		t.Fatalf("unexpected state: %#v", state)
	}
}

func TestRequiredTransactionGuardEnforcementConfigRejectsMissingKey(t *testing.T) {
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "true")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "guard-v1")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", "")
	if err := validateRequiredTransactionGuardEnforcementConfig(); err == nil {
		t.Fatal("required enforcement permit accepted missing private key")
	}
}

func TestTransactionGuardEnforcementRequirementFailsClosedWhenGuardIncomplete(t *testing.T) {
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "true")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "test-key")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize)))

	input := transactionGuardV2Request{TransactionBase64: base64.StdEncoding.EncodeToString([]byte("tx")), Network: "solana-mainnet"}
	assessment := transactionFirewallAssessment{Action: "allow", RiskLevel: "low"}
	updated, state := applyTransactionGuardEnforcementRequirement(input, "req-incomplete", assessment, false, time.Unix(1_700_000_000, 0).UTC())
	if state.Issued || state.Status != "not_eligible" {
		t.Fatalf("state=%#v want not_eligible without permit", state)
	}
	if updated.Action != "withhold" || updated.RiskLevel != "unknown" {
		t.Fatalf("assessment=%#v want fail-closed withhold", updated)
	}
	if got := transactionGuardHTTPStatusWithEnforcement(updated, state); got != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want=%d", got, http.StatusServiceUnavailable)
	}
}
