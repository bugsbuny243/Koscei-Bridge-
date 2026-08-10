package handlers

import (
	"reflect"
	"testing"
	"time"
)

func TestTransactionGuardActorIncidentLinksAndAggregation(t *testing.T) {
	const (
		actorA = "Vote111111111111111111111111111111111111111"
		actorB = "Stake11111111111111111111111111111111111111"
		mintA  = "So11111111111111111111111111111111111111112"
		mintB  = "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA"
	)
	memory := transactionGuardActorMemoryGraph{
		Status: "matches_observed", Complete: true,
		Subjects: []transactionGuardActorMemorySubject{
			{Address: actorA, Matched: true, TokenMints: []string{mintA}},
			{Address: actorB, Matched: true, TokenMints: []string{mintA, mintB}},
		},
	}
	links := transactionGuardActorIncidentLinks(memory)
	if got := links[mintA]; !reflect.DeepEqual(got, []string{actorB, actorA}) && !reflect.DeepEqual(got, []string{actorA, actorB}) {
		t.Fatalf("mintA subjects=%v", got)
	}
	if got := links[mintB]; !reflect.DeepEqual(got, []string{actorB}) {
		t.Fatalf("mintB subjects=%v", got)
	}

	base := transactionGuardActorIncidentMemory{
		Version: transactionGuardActorIncidentMemoryVersion,
		Network: "solana-mainnet", TransactionFingerprint: "tx-sha256:test",
		Status: "no_linked_tokens", Complete: true, ActorMemoryStatus: memory.Status,
		LinkedTokenCount: len(links), Tokens: []transactionGuardActorIncidentToken{}, Limitations: []string{},
		VerdictAuthority: false, RealWorldIdentityClaim: false, WrongdoingClaim: false, SafetyClaim: false,
	}
	rows := []transactionGuardActorIncidentVerdictRow{
		{
			TokenMint: mintA, ModuleID: "repeat_actor_scan", RiskIndex: 92, RiskLevel: "critical", Grade: "F",
			Verdict: "historical critical signed verdict", Source: "security_radar", ObservedAt: time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC),
			Evidence: []string{"signed historical evidence"},
		},
		{
			TokenMint: mintA, ModuleID: "holder_concentration", RiskIndex: 12, RiskLevel: "low", Grade: "A",
			Verdict: "historical low signed verdict", Source: "security_radar", ObservedAt: time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC),
		},
	}
	out := aggregateTransactionGuardActorIncidentMemory(base, links, rows)
	if out.Status != "material_signed_risk_history_observed" {
		t.Fatalf("status=%q", out.Status)
	}
	if out.LinkedTokenCount != 2 || out.SignedHistoryTokenCount != 1 || out.MaterialRiskTokenCount != 1 {
		t.Fatalf("counts linked=%d signed=%d material=%d", out.LinkedTokenCount, out.SignedHistoryTokenCount, out.MaterialRiskTokenCount)
	}
	if out.VerdictAuthority || out.RealWorldIdentityClaim || out.WrongdoingClaim || out.SafetyClaim {
		t.Fatalf("incident memory must remain context-only: %+v", out)
	}
	if len(out.Tokens) != 2 {
		t.Fatalf("tokens=%d", len(out.Tokens))
	}
	var material, noHistory *transactionGuardActorIncidentToken
	for i := range out.Tokens {
		switch out.Tokens[i].TokenMint {
		case mintA:
			material = &out.Tokens[i]
		case mintB:
			noHistory = &out.Tokens[i]
		}
	}
	if material == nil || !material.MaterialRiskHistory || material.SignedVerdictCount != 2 || material.HighestRiskLevel != "critical" || material.HighestRiskIndex != 92 {
		t.Fatalf("material token=%+v", material)
	}
	if noHistory == nil || noHistory.MaterialRiskHistory || noHistory.SignedVerdictCount != 0 {
		t.Fatalf("no-history token=%+v", noHistory)
	}

	hash1 := transactionGuardActorIncidentMemoryHash(out)
	hash2 := transactionGuardActorIncidentMemoryHash(out)
	if hash1 == "" || hash1 != hash2 {
		t.Fatalf("non-deterministic hash: %q %q", hash1, hash2)
	}
}

func TestTransactionGuardActorIncidentMemoryWithholdsWhenActorMemoryIncomplete(t *testing.T) {
	out := (&Handler{}).collectTransactionGuardActorIncidentMemory(
		t.Context(), "solana-mainnet", "tx-sha256:test",
		transactionGuardActorMemoryGraph{Status: "source_unavailable", Complete: false},
	)
	if out.Complete {
		t.Fatal("incident memory must be incomplete when persistent actor memory is incomplete")
	}
	if out.Status != "actor_memory_unavailable" {
		t.Fatalf("status=%q", out.Status)
	}
	if out.VerdictAuthority || out.WrongdoingClaim || out.SafetyClaim {
		t.Fatalf("unavailable incident memory must not acquire authority: %+v", out)
	}
}
