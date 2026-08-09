package handlers

import (
	"crypto/ed25519"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"koschei/api/internal/services"
)

func transactionGuardStateRecheckFixture(t *testing.T, ttl time.Duration) (transactionGuardV2Request, transactionGuardStateWitness, transactionGuardEnforcementPermit, ed25519.PrivateKey, time.Time) {
	t.Helper()
	seed := make([]byte, ed25519.SeedSize)
	for i := range seed {
		seed[i] = byte(100 + i)
	}
	privateKey := ed25519.NewKeyFromSeed(seed)
	input := transactionGuardV2Request{Transaction: "state-recheck-transaction", Network: "solana-mainnet", Encoding: "base64"}
	witness := buildTransactionGuardStateWitness(
		transactionFingerprint(input.Transaction),
		700,
		702,
		[]string{"AddrB", "AddrA"},
		[]*services.SolanaAccountInfo{
			{Lamports: 22, Owner: "OwnerB", Data: []any{"Qg==", "base64"}},
			{Lamports: 11, Owner: "OwnerA", Data: []any{"QQ==", "base64"}},
		},
	)
	if !witness.Complete {
		t.Fatalf("fixture witness incomplete: %#v", witness)
	}
	now := time.Date(2026, 8, 9, 6, 0, 0, 0, time.UTC)
	permit, err := signTransactionGuardEnforcementPermitWithWitness(privateKey, "recheck-key", ttl, input, "req-recheck", transactionFirewallAssessment{Action: "allow"}, now, &witness)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "recheck-key")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(privateKey))
	return input, witness, permit, privateKey, now
}

func TestVerifyTransactionGuardStateBoundPermitForRecheck(t *testing.T) {
	input, witness, permit, _, issuedAt := transactionGuardStateRecheckFixture(t, 90*time.Second)
	claims, err := verifyTransactionGuardStateBoundPermitForRecheck(permit.Token, input.Transaction, input.Network, witness, issuedAt.Add(10*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if claims.Version != transactionGuardStateBoundPermitVersion || claims.StateWitnessHash != witness.BindingHash || claims.StateAccountRoot != witness.AccountRoot {
		t.Fatalf("claims=%#v witness=%#v", claims, witness)
	}
}

func TestVerifyTransactionGuardStateBoundPermitRejectsUntrustedSigner(t *testing.T) {
	input, witness, permit, _, issuedAt := transactionGuardStateRecheckFixture(t, 90*time.Second)
	otherKey := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(otherKey))
	if _, err := verifyTransactionGuardStateBoundPermitForRecheck(permit.Token, input.Transaction, input.Network, witness, issuedAt.Add(time.Second)); !errors.Is(err, errTransactionGuardPermitInvalid) {
		t.Fatalf("err=%v want permit invalid", err)
	}
}

func TestVerifyTransactionGuardStateBoundPermitRejectsExpiredPermit(t *testing.T) {
	input, witness, permit, _, issuedAt := transactionGuardStateRecheckFixture(t, 90*time.Second)
	if _, err := verifyTransactionGuardStateBoundPermitForRecheck(permit.Token, input.Transaction, input.Network, witness, issuedAt.Add(90*time.Second)); !errors.Is(err, errTransactionGuardPermitExpired) {
		t.Fatalf("err=%v want expired", err)
	}
}

func TestVerifyTransactionGuardStateBoundPermitRejectsChangedTransaction(t *testing.T) {
	input, witness, permit, _, issuedAt := transactionGuardStateRecheckFixture(t, 90*time.Second)
	if _, err := verifyTransactionGuardStateBoundPermitForRecheck(permit.Token, input.Transaction+"-changed", input.Network, witness, issuedAt.Add(time.Second)); !errors.Is(err, errTransactionGuardPermitInvalid) {
		t.Fatalf("err=%v want permit invalid", err)
	}
}

func TestVerifyTransactionGuardStateBoundPermitRejectsMutatedWitness(t *testing.T) {
	input, witness, permit, _, issuedAt := transactionGuardStateRecheckFixture(t, 90*time.Second)
	witness.Accounts[0].StateHash = witness.Accounts[1].StateHash
	if _, err := verifyTransactionGuardStateBoundPermitForRecheck(permit.Token, input.Transaction, input.Network, witness, issuedAt.Add(time.Second)); !errors.Is(err, errTransactionGuardPermitInvalid) {
		t.Fatalf("err=%v want permit invalid", err)
	}
}

func TestVerifyTransactionGuardStateBoundPermitRejectsLegacyV1Permit(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	privateKey := ed25519.NewKeyFromSeed(seed)
	input := transactionGuardV2Request{Transaction: "legacy-transaction", Network: "solana-mainnet"}
	now := time.Date(2026, 8, 9, 6, 0, 0, 0, time.UTC)
	permit, err := signTransactionGuardEnforcementPermit(privateKey, "recheck-key", 90*time.Second, input, "req-v1", transactionFirewallAssessment{Action: "allow"}, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "recheck-key")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", base64.StdEncoding.EncodeToString(privateKey))
	witness := unavailableTransactionGuardStateWitness(transactionFingerprint(input.Transaction), 0, "legacy permit has no witness")
	if _, err := verifyTransactionGuardStateBoundPermitForRecheck(permit.Token, input.Transaction, input.Network, witness, now.Add(time.Second)); !errors.Is(err, errTransactionGuardPermitInvalid) {
		t.Fatalf("err=%v want permit invalid", err)
	}
}

func TestTransactionGuardStateRootFromWitnessAccountsIsOrderIndependent(t *testing.T) {
	_, witness, _, _, _ := transactionGuardStateRecheckFixture(t, 90*time.Second)
	forward, err := transactionGuardStateRootFromWitnessAccounts(witness.Accounts)
	if err != nil {
		t.Fatal(err)
	}
	reversed := []transactionGuardStateWitnessAccount{witness.Accounts[1], witness.Accounts[0]}
	backward, err := transactionGuardStateRootFromWitnessAccounts(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if forward != witness.AccountRoot || backward != witness.AccountRoot {
		t.Fatalf("roots forward=%s backward=%s witness=%s", forward, backward, witness.AccountRoot)
	}
}

func TestEvaluateTransactionGuardStateRecheck(t *testing.T) {
	claims := transactionGuardEnforcementPermitClaims{StateAccountRoot: "abcd", SimulationSlot: 100}
	unchanged := evaluateTransactionGuardStateRecheck(claims, "abcd", 105)
	if unchanged.Status != "state_unchanged" || !unchanged.StateUnchanged || unchanged.RequiresResimulation || unchanged.Action != "permit_state_consistent" || unchanged.SlotAdvance != 5 {
		t.Fatalf("unchanged=%#v", unchanged)
	}
	changed := evaluateTransactionGuardStateRecheck(claims, "dcba", 105)
	if changed.Status != "state_changed" || changed.StateUnchanged || !changed.RequiresResimulation || changed.Action != "recheck_required" {
		t.Fatalf("changed=%#v", changed)
	}
	stale := evaluateTransactionGuardStateRecheck(claims, "abcd", 99)
	if stale.Status != "withhold" || stale.StateUnchanged || !stale.RequiresResimulation {
		t.Fatalf("stale=%#v", stale)
	}
	missing := evaluateTransactionGuardStateRecheck(claims, "", 105)
	if missing.Status != "withhold" || !missing.RequiresResimulation {
		t.Fatalf("missing=%#v", missing)
	}
}
