package handlers

import (
	"encoding/base64"
	"testing"

	"koschei/api/internal/services"
)

func TestTransactionGuardStateWitnessDeterministicAcrossInputOrder(t *testing.T) {
	accountA := &services.SolanaAccountInfo{
		Data:     []any{base64.StdEncoding.EncodeToString([]byte("state-a")), "base64"},
		Lamports: 100,
		Owner:    "OwnerA",
		Space:    165,
	}
	accountB := &services.SolanaAccountInfo{
		Data:     []any{base64.StdEncoding.EncodeToString([]byte("state-b")), "base64"},
		Lamports: 200,
		Owner:    "OwnerB",
		Space:    165,
	}
	first := buildTransactionGuardStateWitness("fingerprint", 1000, 1002, []string{"AddrB", "AddrA"}, []*services.SolanaAccountInfo{accountB, accountA})
	second := buildTransactionGuardStateWitness("fingerprint", 1000, 1002, []string{"AddrA", "AddrB"}, []*services.SolanaAccountInfo{accountA, accountB})

	if !first.Complete || first.Status != "complete" || !second.Complete {
		t.Fatalf("witness incomplete: first=%#v second=%#v", first, second)
	}
	if first.AccountRoot != second.AccountRoot || first.BindingHash != second.BindingHash {
		t.Fatalf("order changed witness identity: root %s/%s binding %s/%s", first.AccountRoot, second.AccountRoot, first.BindingHash, second.BindingHash)
	}
	if first.SlotSpread != 2 {
		t.Fatalf("slot spread=%d want 2", first.SlotSpread)
	}
	if len(first.Accounts) != 2 || first.Accounts[0].Address != "AddrA" || first.Accounts[1].Address != "AddrB" {
		t.Fatalf("accounts not canonicalized: %#v", first.Accounts)
	}
}

func TestTransactionGuardStateWitnessChangesWhenAccountStateChanges(t *testing.T) {
	before := &services.SolanaAccountInfo{Lamports: 100, Owner: "OwnerA", Data: []any{"AA==", "base64"}}
	after := &services.SolanaAccountInfo{Lamports: 101, Owner: "OwnerA", Data: []any{"AA==", "base64"}}
	first := buildTransactionGuardStateWitness("fingerprint", 10, 11, []string{"AddrA"}, []*services.SolanaAccountInfo{before})
	second := buildTransactionGuardStateWitness("fingerprint", 10, 11, []string{"AddrA"}, []*services.SolanaAccountInfo{after})
	if !first.Complete || !second.Complete {
		t.Fatalf("expected complete witnesses: %#v %#v", first, second)
	}
	if first.AccountRoot == second.AccountRoot || first.BindingHash == second.BindingHash {
		t.Fatal("changed account state did not change witness identity")
	}
}

func TestTransactionGuardStateWitnessBindsSlotsAndTransaction(t *testing.T) {
	account := &services.SolanaAccountInfo{Lamports: 100, Owner: "OwnerA", Data: []any{"AA==", "base64"}}
	base := buildTransactionGuardStateWitness("fingerprint-a", 10, 11, []string{"AddrA"}, []*services.SolanaAccountInfo{account})
	otherTransaction := buildTransactionGuardStateWitness("fingerprint-b", 10, 11, []string{"AddrA"}, []*services.SolanaAccountInfo{account})
	otherSimulationSlot := buildTransactionGuardStateWitness("fingerprint-a", 10, 12, []string{"AddrA"}, []*services.SolanaAccountInfo{account})
	if base.BindingHash == otherTransaction.BindingHash {
		t.Fatal("transaction fingerprint was not bound into witness")
	}
	if base.BindingHash == otherSimulationSlot.BindingHash {
		t.Fatal("simulation slot was not bound into witness")
	}
}

func TestTransactionGuardStateWitnessRepresentsMissingAccount(t *testing.T) {
	witness := buildTransactionGuardStateWitness("fingerprint", 50, 50, []string{"MissingAddr"}, []*services.SolanaAccountInfo{nil})
	if !witness.Complete || len(witness.Accounts) != 1 {
		t.Fatalf("unexpected missing-account witness: %#v", witness)
	}
	if witness.Accounts[0].Present || witness.Accounts[0].StateHash == "" {
		t.Fatalf("missing account not represented deterministically: %#v", witness.Accounts[0])
	}
}

func TestTransactionGuardStateWitnessFailsClosedWithoutSlotsOrAlignedAccounts(t *testing.T) {
	account := &services.SolanaAccountInfo{Lamports: 100}
	noSlot := buildTransactionGuardStateWitness("fingerprint", 0, 10, []string{"AddrA"}, []*services.SolanaAccountInfo{account})
	if noSlot.Complete || noSlot.Status != "incomplete" || len(noSlot.Limitations) == 0 {
		t.Fatalf("missing slot accepted: %#v", noSlot)
	}
	misaligned := buildTransactionGuardStateWitness("fingerprint", 10, 10, []string{"AddrA", "AddrB"}, []*services.SolanaAccountInfo{account})
	if misaligned.Complete || misaligned.Status != "incomplete" {
		t.Fatalf("misaligned account evidence accepted: %#v", misaligned)
	}
}
