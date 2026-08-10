package services

import "testing"

func TestCampaignEvidenceDependencyLedgerGroupsTrajectorySignalsTogether(t *testing.T) {
	report := BehavioralSignatureReport{
		Complete: true,
		Matches: []BehavioralSignatureMatch{
			{
				SignatureID: "KOSCH-BEH-006", Label: "trajectory", Triggered: true, EvidenceStatus: "observed",
				ActorWallets: []string{"ActorA", "ActorB"}, Targets: []string{"TokenA", "TokenB"},
				FundingSources: []string{"Funder1"}, EvidenceRefs: []string{"fund-a", "exit-a", "sha256:graph"},
			},
			{
				SignatureID: "KOSCH-BEH-007", Label: "tempo", Triggered: true, EvidenceStatus: "observed",
				ActorWallets: []string{"ActorA", "ActorB"}, Targets: []string{"TokenA", "TokenB"},
				FundingSources: []string{"Funder1"}, EvidenceRefs: []string{"fund-a", "exit-a", "sha256:graph", "sha256:tempo"},
			},
		},
	}
	ledger := BuildCampaignEvidenceDependencyLedger(report)
	if ledger.Status != "dependency_ledger_available" || ledger.TriggeredAnchorCount != 2 {
		t.Fatalf("unexpected ledger: %+v", ledger)
	}
	if ledger.DistinctDependencyGroups != 1 {
		t.Fatalf("BEH-006 and BEH-007 must count as one dependency group, got %+v", ledger)
	}
	if ledger.IndependenceProvenAnchors != 0 || ledger.IndependenceUnprovenAnchors != 2 {
		t.Fatalf("trajectory-derived anchors must not acquire independence claim: %+v", ledger)
	}
	if len(ledger.Overlaps) != 1 || !ledger.Overlaps[0].SameGroup {
		t.Fatalf("expected explicit same-group overlap: %+v", ledger.Overlaps)
	}
	if ledger.VerdictAuthority || ledger.GradeAuthority || ledger.SameOperatorClaim || ledger.RealWorldIdentityClaim || ledger.WrongdoingClaim {
		t.Fatalf("dependency ledger acquired prohibited authority: %+v", ledger)
	}
}

func TestCampaignEvidenceDependencyLedgerGroupsExactIncidentSummariesTogether(t *testing.T) {
	report := BehavioralSignatureReport{
		Complete: true,
		Matches: []BehavioralSignatureMatch{
			{SignatureID: "KOSCH-BEH-001", Triggered: true, EvidenceStatus: "verified", EvidenceRefs: []string{"event-a", "verdict-a"}},
			{SignatureID: "KOSCH-BEH-002", Triggered: true, EvidenceStatus: "verified", EvidenceRefs: []string{"event-a", "verdict-a"}},
			{SignatureID: "KOSCH-BEH-003", Triggered: true, EvidenceStatus: "observed", EvidenceRefs: []string{"signed-history"}},
		},
	}
	ledger := BuildCampaignEvidenceDependencyLedger(report)
	if ledger.TriggeredAnchorCount != 3 || ledger.DistinctDependencyGroups != 2 {
		t.Fatalf("expected incident summaries + funding outcome to form two groups: %+v", ledger)
	}
	foundIncidentOverlap := false
	for _, overlap := range ledger.Overlaps {
		if overlap.AnchorA == "KOSCH-BEH-001" && overlap.AnchorB == "KOSCH-BEH-002" && overlap.SameGroup {
			foundIncidentOverlap = true
		}
	}
	if !foundIncidentOverlap {
		t.Fatalf("exact-incident double count was not exposed: %+v", ledger.Overlaps)
	}
}

func TestCampaignEvidenceDependencyLedgerWithholdsGenomeIndependence(t *testing.T) {
	report := BehavioralSignatureReport{
		Complete: true,
		Matches: []BehavioralSignatureMatch{
			{SignatureID: "KOSCH-BEH-005", Label: "genome", Triggered: true, EvidenceStatus: "observed", EvidenceRefs: []string{"genome-snapshot"}},
			{SignatureID: "KOSCH-BEH-006", Label: "trajectory", Triggered: true, EvidenceStatus: "observed", EvidenceRefs: []string{"trajectory-graph"}},
		},
	}
	ledger := BuildCampaignEvidenceDependencyLedger(report)
	if ledger.DistinctDependencyGroups != 2 {
		t.Fatalf("different dependency groups should remain visible: %+v", ledger)
	}
	var genome *CampaignEvidenceDependencyAnchor
	for i := range ledger.Anchors {
		if ledger.Anchors[i].AnchorID == "KOSCH-BEH-005" {
			genome = &ledger.Anchors[i]
			break
		}
	}
	if genome == nil || genome.IndependenceStatus != "not_independence_proven" {
		t.Fatalf("genome independence must be withheld: %+v", genome)
	}
	if ledger.IndependenceProvenAnchors != 0 {
		t.Fatalf("v1 must not manufacture independent confirmations: %+v", ledger)
	}
}

func TestCampaignEvidenceDependencyLedgerUnknownFamilyFailsConservative(t *testing.T) {
	ledger := BuildCampaignEvidenceDependencyLedger(BehavioralSignatureReport{
		Complete: true,
		Matches: []BehavioralSignatureMatch{{SignatureID: "KOSCH-BEH-999", Triggered: true, EvidenceStatus: "observed"}},
	})
	if len(ledger.Anchors) != 1 || ledger.Anchors[0].DependencyGroup != "unknown_behavior_family" {
		t.Fatalf("unknown behavior family must be explicit and conservative: %+v", ledger)
	}
	if ledger.Anchors[0].IndependenceStatus != "not_independence_proven" {
		t.Fatalf("unknown family independence must be withheld: %+v", ledger.Anchors[0])
	}
}
