package handlers

import (
	"encoding/json"
	"strings"
	"testing"

	"koschei/api/internal/web3"
)

func TestStateRecheckCourtCanonicalizerBuildsSameRootAcrossSlots(t *testing.T) {
	canonicalize := transactionGuardStateRecheckCourtCanonicalizer([]string{"AccountA"})
	first := json.RawMessage(`{"context":{"slot":120},"value":[{"data":["AQID","base64"],"executable":false,"lamports":42,"owner":"OwnerA","rentEpoch":7,"space":3}]}`)
	second := json.RawMessage(`{"context":{"slot":135},"value":[{"data":["AQID","base64"],"executable":false,"lamports":42,"owner":"OwnerA","rentEpoch":7,"space":3}]}`)

	firstRoot, firstSlot, _, err := canonicalize(first)
	if err != nil {
		t.Fatalf("first canonicalization: %v", err)
	}
	secondRoot, secondSlot, _, err := canonicalize(second)
	if err != nil {
		t.Fatalf("second canonicalization: %v", err)
	}
	if firstRoot == "" || firstRoot != secondRoot {
		t.Fatalf("roots differ: %q != %q", firstRoot, secondRoot)
	}
	if firstSlot != 120 || secondSlot != 135 {
		t.Fatalf("slots=%d,%d", firstSlot, secondSlot)
	}
}

func TestStateRecheckCourtFreshVerifiedQuorumKeepsPermitConsistent(t *testing.T) {
	decision := transactionGuardStateRecheckDecision{
		Status: "state_unchanged", Action: "permit_state_consistent", StateUnchanged: true,
		RequiresResimulation: false, CurrentStateRoot: "root-a", SimulationSlot: 100,
	}
	court := web3.EvidenceCourtResult{
		Enabled: true, Status: "verified", Required: 2, ValueHash: "root-a",
		Witnesses: []web3.EvidenceCourtWitness{
			{Provider: "alchemy", Status: "observed", ValueHash: "root-a", ContextSlot: 101},
			{Provider: "helius", Status: "observed", ValueHash: "root-a", ContextSlot: 105},
		},
	}
	got := applyTransactionGuardStateRecheckEvidenceCourt(decision, court)
	if got.Status != "state_unchanged" || !got.StateUnchanged || got.RequiresResimulation {
		t.Fatalf("decision=%#v", got)
	}
	if !strings.Contains(got.Reason, "corroborated") {
		t.Fatalf("reason=%q", got.Reason)
	}
}

func TestStateRecheckCourtStaleQuorumFailsClosed(t *testing.T) {
	decision := transactionGuardStateRecheckDecision{
		Status: "state_unchanged", Action: "permit_state_consistent", StateUnchanged: true,
		RequiresResimulation: false, CurrentStateRoot: "root-a", SimulationSlot: 100,
	}
	court := web3.EvidenceCourtResult{
		Enabled: true, Status: "verified", Required: 2, ValueHash: "root-a",
		Witnesses: []web3.EvidenceCourtWitness{
			{Provider: "alchemy", Status: "observed", ValueHash: "root-a", ContextSlot: 99},
			{Provider: "helius", Status: "observed", ValueHash: "root-a", ContextSlot: 105},
		},
	}
	got := applyTransactionGuardStateRecheckEvidenceCourt(decision, court)
	if got.Status != "withhold" || !got.RequiresResimulation || got.StateUnchanged {
		t.Fatalf("decision=%#v", got)
	}
}

func TestStateRecheckCourtPrimaryRootDisagreementFailsClosed(t *testing.T) {
	decision := transactionGuardStateRecheckDecision{
		Status: "state_unchanged", Action: "permit_state_consistent", StateUnchanged: true,
		RequiresResimulation: false, CurrentStateRoot: "primary-root", SimulationSlot: 100,
	}
	court := web3.EvidenceCourtResult{
		Enabled: true, Status: "verified", Required: 2, ValueHash: "court-root",
		Witnesses: []web3.EvidenceCourtWitness{
			{Provider: "alchemy", Status: "observed", ValueHash: "court-root", ContextSlot: 101},
			{Provider: "helius", Status: "observed", ValueHash: "court-root", ContextSlot: 102},
		},
	}
	got := applyTransactionGuardStateRecheckEvidenceCourt(decision, court)
	if got.Status != "withhold" || !strings.Contains(got.Reason, "disagrees") {
		t.Fatalf("decision=%#v", got)
	}
}

func TestStateRecheckCourtConflictFailsClosed(t *testing.T) {
	decision := transactionGuardStateRecheckDecision{
		Status: "state_unchanged", Action: "permit_state_consistent", StateUnchanged: true,
		RequiresResimulation: false, CurrentStateRoot: "root-a", SimulationSlot: 100,
	}
	court := web3.EvidenceCourtResult{Enabled: true, Status: "conflict", Required: 2}
	got := applyTransactionGuardStateRecheckEvidenceCourt(decision, court)
	if got.Status != "withhold" || !got.RequiresResimulation {
		t.Fatalf("decision=%#v", got)
	}
}

func TestStateRecheckCourtDisabledPreservesSingleProviderDecision(t *testing.T) {
	decision := transactionGuardStateRecheckDecision{
		Status: "state_unchanged", Action: "permit_state_consistent", StateUnchanged: true,
		RequiresResimulation: false, CurrentStateRoot: "root-a", SimulationSlot: 100,
	}
	got := applyTransactionGuardStateRecheckEvidenceCourt(decision, web3.EvidenceCourtResult{Enabled: false, Status: "disabled"})
	if got != decision {
		t.Fatalf("decision changed while court disabled: %#v", got)
	}
}

func TestStateRecheckCourtPublicResponseRedactsProviderHost(t *testing.T) {
	court := web3.EvidenceCourtResult{
		SchemaVersion: "koschei-evidence-court-v1",
		Enabled:       true,
		Status:        "verified",
		Required:      2,
		Witnesses: []web3.EvidenceCourtWitness{
			{Provider: "alchemy", Host: "private-rpc.internal.example", Status: "observed", ValueHash: "root-a", ContextSlot: 101},
		},
	}
	encoded, err := json.Marshal(transactionGuardStateRecheckCourtPublicResponse(court))
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	if strings.Contains(body, "private-rpc.internal.example") || strings.Contains(body, `"host"`) {
		t.Fatalf("provider host leaked in public response: %s", body)
	}
	if !strings.Contains(body, `"provider":"alchemy"`) || !strings.Contains(body, `"context_slot":101`) {
		t.Fatalf("expected safe witness metadata missing: %s", body)
	}
}
