package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestAttachCustomerAttackPathExposesConcreteEvidenceProjection(t *testing.T) {
	assembly := unifiedInvestigationAssembly{
		Report: map[string]any{
			"threat_anticipation": services.ThreatAnticipationReport{
				Target: "Mint111",
				Status: "evidence_backed_pathway_analysis",
				Pathways: []services.ThreatPathway{
					{ID: "creator_sell_acceleration", Status: "observed", EvidenceStatus: "observed"},
				},
			},
			"evidence_references": map[string]unifiedEvidenceReference{
				"creator-sell": {
					Wallets:      []string{"Creator111"},
					Signatures:   []string{"CreatorSellSig111"},
					Slots:        []int64{300},
					EvidenceKeys: []string{"creator-sell:CreatorSellSig111"},
				},
			},
		},
	}

	attachCustomerAttackPath(&assembly)
	attackPath, ok := assembly.Report["attack_path"].(map[string]any)
	if !ok {
		t.Fatalf("customer report did not expose attack_path: %#v", assembly.Report["attack_path"])
	}
	linked, ok := attackPath["evidence_references"].(map[string]unifiedEvidenceReference)
	if !ok {
		t.Fatalf("customer attack_path did not preserve concrete evidence references: %#v", attackPath["evidence_references"])
	}
	creator := linked["creator_sell_acceleration"]
	assertContainsString(t, creator.Wallets, "Creator111")
	assertContainsString(t, creator.Signatures, "CreatorSellSig111")
	assertContainsInt64(t, creator.Slots, 300)
}

func TestAttachCustomerAttackPathRejectsUntypedThreatData(t *testing.T) {
	assembly := unifiedInvestigationAssembly{Report: map[string]any{
		"threat_anticipation": map[string]any{"status": "fake"},
	}}
	attachCustomerAttackPath(&assembly)
	if _, exists := assembly.Report["attack_path"]; exists {
		t.Fatal("customer attack_path must not be fabricated from untyped threat data")
	}
}
