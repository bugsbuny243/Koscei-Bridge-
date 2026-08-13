package services

import "testing"

func TestAugmentThreatAnticipationOperationalMemoryIsWatchOnly(t *testing.T) {
	base := ThreatAnticipationReport{
		Status:          "evidence_backed_pathway_analysis",
		PrimaryExposure: "existing primary exposure",
		Pathways:        []ThreatPathway{},
		Scenarios:       []ThreatScenario{},
		EvidencePolicy:  map[string]bool{"deterministic_verdict_remains_authoritative": true},
	}
	memory := ActorOperationalMemoryReport{
		Available: true,
		Matches: []ActorOperationalMatch{{
			Wallet: "candidate", Classification: "repeated_operational_overlap", EvidenceStatus: "observed",
			Rules: []string{"AOM-03"}, SharedCounterpartCount: 2, SharedRelationCount: 2,
		}},
	}
	out := AugmentThreatAnticipationWithOperationalMemory(base, memory)
	if len(out.Pathways) != 1 || out.Pathways[0].Status != "watch" {
		t.Fatalf("operational memory must remain a watch pathway: %#v", out.Pathways)
	}
	if out.PrimaryExposure != base.PrimaryExposure {
		t.Fatal("operational memory must not replace evidence-backed primary exposure")
	}
	if out.EvidencePolicy["operational_memory_can_change_grade"] {
		t.Fatal("operational memory must not change deterministic grade")
	}
	if out.EvidencePolicy["operational_overlap_proves_identity"] {
		t.Fatal("operational overlap must never prove identity")
	}
}

func TestAugmentThreatAnticipationNoMatchAddsNoPath(t *testing.T) {
	base := ThreatAnticipationReport{Pathways: []ThreatPathway{}, Scenarios: []ThreatScenario{}}
	out := AugmentThreatAnticipationWithOperationalMemory(base, ActorOperationalMemoryReport{Available: false})
	if len(out.Pathways) != 0 || len(out.Scenarios) != 0 {
		t.Fatalf("no operational match must create no threat narrative: %#v", out)
	}
}

func TestThreatOperationalMemoryVerifiedLinkStillDoesNotPredictIntent(t *testing.T) {
	base := ThreatAnticipationReport{Pathways: []ThreatPathway{}, Scenarios: []ThreatScenario{}}
	memory := ActorOperationalMemoryReport{
		Available: true,
		Matches: []ActorOperationalMatch{{
			Wallet: "counterparty", Classification: "verified_counterparty_link", EvidenceStatus: "verified",
			Rules: []string{"AOM-01"}, DirectVerifiedRelations: 2,
		}},
	}
	out := AugmentThreatAnticipationWithOperationalMemory(base, memory)
	if len(out.Pathways) != 1 || out.Pathways[0].EvidenceStatus != "verified" {
		t.Fatalf("verified interaction evidence should remain verified: %#v", out.Pathways)
	}
	if out.Pathways[0].Capacity != "unknown" || out.Pathways[0].Status != "watch" {
		t.Fatalf("verified counterparty interaction must not become attack capacity: %#v", out.Pathways[0])
	}
	if out.EvidencePolicy["operational_overlap_predicts_intent"] {
		t.Fatal("operational overlap must not predict intent")
	}
}
