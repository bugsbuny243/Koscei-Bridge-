package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"koschei/api/internal/services"
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
	if permit.Version != transactionGuardEnforcementPermitVersion {
		t.Fatalf("permit version=%s want legacy v1", permit.Version)
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
	if claims.StateWitnessHash != "" || claims.StateWitnessVersion != "" {
		t.Fatalf("legacy permit unexpectedly contains state witness: %#v", claims)
	}
	expires, _ := time.Parse(time.RFC3339Nano, claims.ExpiresAt)
	if expires.Sub(now) != 90*time.Second {
		t.Fatalf("ttl=%s", expires.Sub(now))
	}
}

func TestTransactionGuardStateBoundPermitBindsWitness(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(200 - i)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	input := transactionGuardV2Request{Transaction: "fixture-transaction", Network: "solana-mainnet", Wallet: "Wallet111"}
	witness := buildTransactionGuardStateWitness(
		transactionFingerprint(input.Transaction),
		100,
		101,
		[]string{"AddrA"},
		[]*services.SolanaAccountInfo{{Lamports: 123, Owner: "OwnerA", Data: []any{"AA==", "base64"}}},
	)
	if !witness.Complete {
		t.Fatalf("fixture witness incomplete: %#v", witness)
	}
	permit, err := signTransactionGuardEnforcementPermitWithWitness(privateKey, "guard-v2", 90*time.Second, input, "req-state", transactionFirewallAssessment{Action: "allow"}, time.Unix(1_800_000_000, 0).UTC(), &witness)
	if err != nil {
		t.Fatal(err)
	}
	if permit.Version != transactionGuardStateBoundPermitVersion || permit.Claims.Version != transactionGuardStateBoundPermitVersion {
		t.Fatalf("state-bound permit version mismatch: %#v", permit)
	}
	if permit.Claims.StateWitnessVersion != witness.Version || permit.Claims.StateWitnessHash != witness.BindingHash || permit.Claims.StateAccountRoot != witness.AccountRoot {
		t.Fatalf("state witness claims not bound: %#v witness=%#v", permit.Claims, witness)
	}
	if permit.Claims.PreStateSlot != 100 || permit.Claims.SimulationSlot != 101 {
		t.Fatalf("state slots not bound: %#v", permit.Claims)
	}
}

func TestTransactionGuardStateBoundPermitRejectsWitnessForDifferentTransaction(t *testing.T) {
	privateKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	input := transactionGuardV2Request{Transaction: "transaction-a", Network: "solana-mainnet"}
	witness := buildTransactionGuardStateWitness(
		transactionFingerprint("transaction-b"),
		100,
		101,
		[]string{"AddrA"},
		[]*services.SolanaAccountInfo{{Lamports: 1}},
	)
	if _, err := signTransactionGuardEnforcementPermitWithWitness(privateKey, "guard-v2", 90*time.Second, input, "req", transactionFirewallAssessment{Action: "allow"}, time.Now(), &witness); err == nil {
		t.Fatal("permit accepted a state witness for a different transaction")
	}
}

func TestTransactionGuardEnforcementStateFailsClosedWhenRequiredSignerInvalid(t *testing.T) {
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "true")
	t.Setenv("TRANSACTION_GUARD_REQUIRE_STATE_WITNESS", "false")
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
	t.Setenv("TRANSACTION_GUARD_REQUIRE_STATE_WITNESS", "false")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "guard-v1")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(seed))
	state := buildTransactionGuardEnforcementState(transactionGuardV2Request{Transaction: "fixture", Network: "solana-mainnet"}, "req", transactionFirewallAssessment{Action: "warn"}, true, time.Now())
	if state.Issued || state.Status != "not_eligible" {
		t.Fatalf("unexpected state: %#v", state)
	}
}

func TestRequiredTransactionGuardEnforcementConfigRejectsMissingKey(t *testing.T) {
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "true")
	t.Setenv("TRANSACTION_GUARD_REQUIRE_STATE_WITNESS", "false")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "guard-v1")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", "")
	if err := validateRequiredTransactionGuardEnforcementConfig(); err == nil {
		t.Fatal("required enforcement permit accepted missing private key")
	}
}

func TestRequiredStateWitnessConfigRequiresPermit(t *testing.T) {
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "false")
	t.Setenv("TRANSACTION_GUARD_REQUIRE_STATE_WITNESS", "true")
	if err := validateRequiredTransactionGuardEnforcementConfig(); err == nil {
		t.Fatal("state witness enforcement accepted without signed permit enforcement")
	}
}

func TestRequiredStateWitnessFailsClosedUntilWitnessIsIntegrated(t *testing.T) {
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "true")
	t.Setenv("TRANSACTION_GUARD_REQUIRE_STATE_WITNESS", "true")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "test-key")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize)))
	assessment := transactionFirewallAssessment{Action: "allow", RiskLevel: "low"}
	updated, state := applyTransactionGuardEnforcementRequirement(transactionGuardV2Request{Transaction: "fixture", Network: "solana-mainnet"}, "req", assessment, true, time.Now())
	if state.Issued || state.Status != "state_witness_unavailable" || !state.StateWitnessRequired {
		t.Fatalf("unexpected state: %#v", state)
	}
	if updated.Action != "withhold" || updated.RiskLevel != "unknown" {
		t.Fatalf("assessment=%#v want state-witness withhold", updated)
	}
}

func TestTransactionGuardEnforcementRequirementFailsClosedWhenGuardIncomplete(t *testing.T) {
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "true")
	t.Setenv("TRANSACTION_GUARD_REQUIRE_STATE_WITNESS", "false")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "test-key")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(make([]byte, ed25519.SeedSize)))

	input := transactionGuardV2Request{Transaction: base64.StdEncoding.EncodeToString([]byte("tx")), Network: "solana-mainnet"}
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
