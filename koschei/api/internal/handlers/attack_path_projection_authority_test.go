package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestAttackPathProjectionLinksAuthorityEvidenceReferences(t *testing.T) {
	threat := services.ThreatAnticipationReport{
		Target: "MintAuthority111",
		Pathways: []services.ThreatPathway{
			{ID: "mint_inflation", Status: "open", EvidenceStatus: "observed"},
			{ID: "freeze_abuse", Status: "open", EvidenceStatus: "observed"},
		},
	}
	report := map[string]any{
		"threat_anticipation": threat,
		"evidence_references": map[string]unifiedEvidenceReference{
			"mint": {
				Accounts:     []string{"MintAuthority111", "MintAuthorityAccount111"},
				Slots:        []int64{410},
				EvidenceKeys: []string{"mint-authority:MintAuthorityAccount111@410"},
			},
			"freeze": {
				Accounts:     []string{"MintAuthority111", "FreezeAuthorityAccount111"},
				Slots:        []int64{411},
				EvidenceKeys: []string{"freeze-authority:FreezeAuthorityAccount111@411"},
			},
		},
	}

	projection, ok := attackPathProjectionFromReport(report)
	if !ok {
		t.Fatal("expected typed attack path projection")
	}
	linked, ok := projection["evidence_references"].(map[string]unifiedEvidenceReference)
	if !ok {
		t.Fatalf("expected authority evidence links, got %#v", projection["evidence_references"])
	}
	mint := linked["mint_inflation"]
	assertContainsString(t, mint.Accounts, "MintAuthorityAccount111")
	assertContainsInt64(t, mint.Slots, 410)
	freeze := linked["freeze_abuse"]
	assertContainsString(t, freeze.Accounts, "FreezeAuthorityAccount111")
	assertContainsInt64(t, freeze.Slots, 411)
}
