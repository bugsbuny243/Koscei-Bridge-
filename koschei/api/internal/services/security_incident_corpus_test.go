package services

import (
	"strings"
	"testing"
	"time"
)

func TestSecurityIncidentCorpusIdentityIsDeterministicAndVersioned(t *testing.T) {
	candidate := securityIncidentCorpusCandidate{
		ActorWallet:        "Actor11111111111111111111111111111111111111",
		EventKind:          ActorExitEventLiquidityRemoval,
		SourceRuleID:       ActorRuleHardCreatorLiquidityRemoval,
		EventSignature:     "event-signature-1",
		EventSlot:          123456,
		EventObservedAt:    time.Date(2026, 8, 1, 10, 0, 0, 0, time.UTC),
		VerdictID:          "11111111-1111-4111-8111-111111111111",
		VerdictSignature:   "signed-verdict-1",
		VerdictUpdatedAt:   time.Date(2026, 8, 1, 10, 1, 0, 0, time.UTC),
		VerdictRuleVersion: "final-v1",
		Grade:              "F",
		RiskIndex:          91,
		RiskLevel:          "critical",
		Verdict:            "material signed historical verdict",
		Recommendation:     "review evidence",
		EvidenceRaw:        []byte(`["verified evidence"]`),
		SignalsRaw:         []byte(`{"verified_evidence":true,"real_onchain_evidence":true}`),
		VerdictSource:      "security_radar",
	}

	first, err := securityIncidentCorpusRecordFromCandidate("solana-mainnet", "Mint111111111111111111111111111111111111111", candidate)
	if err != nil {
		t.Fatal(err)
	}
	second, err := securityIncidentCorpusRecordFromCandidate("solana-mainnet", "Mint111111111111111111111111111111111111111", candidate)
	if err != nil {
		t.Fatal(err)
	}
	if first.IncidentKey != second.IncidentKey || first.RecordHash != second.RecordHash {
		t.Fatalf("same evidence must be byte-stable: first=%+v second=%+v", first, second)
	}
	if !strings.HasPrefix(first.IncidentKey, "KIC1-") || len(first.IncidentKey) != len("KIC1-")+64 {
		t.Fatalf("incident key=%q", first.IncidentKey)
	}
	if !strings.HasPrefix(first.RecordHash, "sha256:") || len(first.RecordHash) != len("sha256:")+64 {
		t.Fatalf("record hash=%q", first.RecordHash)
	}
	if first.RiskLevel != "critical" {
		t.Fatalf("risk level=%q", first.RiskLevel)
	}

	candidate.VerdictUpdatedAt = candidate.VerdictUpdatedAt.Add(time.Minute)
	revised, err := securityIncidentCorpusRecordFromCandidate("solana-mainnet", "Mint111111111111111111111111111111111111111", candidate)
	if err != nil {
		t.Fatal(err)
	}
	if revised.IncidentKey == first.IncidentKey {
		t.Fatal("a later verdict revision must materialize as a new incident version")
	}
}

func TestSecurityIncidentCorpusRejectsIncompleteEvidenceReferences(t *testing.T) {
	candidate := securityIncidentCorpusCandidate{
		ActorWallet:        "actor",
		EventKind:          ActorExitEventLiquidityRemoval,
		SourceRuleID:       ActorRuleHardCreatorLiquidityRemoval,
		EventSignature:     "",
		EventSlot:          0,
		EventObservedAt:    time.Now().UTC(),
		VerdictID:          "11111111-1111-4111-8111-111111111111",
		VerdictSignature:   "verdict",
		VerdictUpdatedAt:   time.Now().UTC(),
		VerdictRuleVersion: "final-v1",
		RiskIndex:          80,
		RiskLevel:          "critical",
	}
	if _, err := securityIncidentCorpusRecordFromCandidate("solana-mainnet", "mint", candidate); err == nil {
		t.Fatal("signature + slot gaps must fail closed")
	}
}

func TestSecurityIncidentCorpusMaterialRiskNormalization(t *testing.T) {
	cases := []struct {
		level string
		index int
		want  string
	}{
		{level: "critical", index: 70, want: "critical"},
		{level: "high", index: 95, want: "high"},
		{level: "medium", index: 85, want: "critical"},
		{level: "medium", index: 65, want: "high"},
	}
	for _, tc := range cases {
		if got := securityIncidentMaterialRiskLevel(tc.level, tc.index); got != tc.want {
			t.Fatalf("level=%s index=%d got=%s want=%s", tc.level, tc.index, got, tc.want)
		}
	}
}
