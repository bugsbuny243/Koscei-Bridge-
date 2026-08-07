package handlers

import "testing"

func TestMetadataImpersonationDeliberatelyRemainsNotInvestigated(t *testing.T) {
	def, ok := signalDefinitionByID("metadata")
	if !ok {
		t.Fatal("metadata registry row missing")
	}
	if def.Source.Kind != signalSourceReport || def.Source.Key != "metadata_impersonation" {
		t.Fatalf("metadata source=%#v", def.Source)
	}
	// Deliberate contract: no verifiable metadata-identity / impersonation
	// detector exists yet. Until one collects attributable evidence, this card
	// stays not_investigated; borrowing an unrelated detector would fabricate an
	// observed state and violate the dossier evidence contract.
	state, _ := signalStateFor(dossierChangeFixture(), def)
	if state != signalStateNotInvestigated {
		t.Fatalf("metadata state=%q want=%q", state, signalStateNotInvestigated)
	}
}

func TestFundingRegistryLineageUsesFundingClusterDetector(t *testing.T) {
	def, ok := signalDefinitionByID("funding")
	if !ok {
		t.Fatal("funding registry row missing")
	}
	if def.Source.Kind != signalSourceModule || def.Source.Key != "funding_cluster_detector" {
		t.Fatalf("funding source=%#v", def.Source)
	}
	if !def.RequireRefs {
		t.Fatal("funding row must require references")
	}
}
