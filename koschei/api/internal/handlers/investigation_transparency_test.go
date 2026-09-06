package handlers

import "testing"

func TestInvestigationTransparencySeparatesEvidenceLimitsFromCollectionGaps(t *testing.T) {
	coverage := canonicalIntegrationCoverage{Capabilities: map[string]canonicalCapabilityStatus{
		"bounded_history": {
			Capability:  "Bounded address history",
			Status:      canonicalCapabilityPartial,
			Source:      "address_history",
			Limitations: []string{"Older activity may exist outside the bounded observation window; absence here is not proof of absence."},
		},
		"exit_liquidity": {
			Capability:  "Jupiter exit liquidity",
			Status:      canonicalCapabilityUnavailable,
			Source:      "exit_liquidity",
			Limitations: []string{"JUPITER_API_KEY is required for the official quote endpoint."},
		},
	}}

	got := buildInvestigationTransparency(coverage)
	if len(got.EvidenceLimits) != 1 {
		t.Fatalf("evidence_limits=%d want 1: %#v", len(got.EvidenceLimits), got.EvidenceLimits)
	}
	if got.EvidenceLimits[0].Remediable {
		t.Fatal("bounded evidence limitation must not be presented as a remediable collection gap")
	}
	if len(got.CollectionGaps) != 1 {
		t.Fatalf("collection_gaps=%d want 1: %#v", len(got.CollectionGaps), got.CollectionGaps)
	}
	if !got.CollectionGaps[0].Remediable {
		t.Fatal("missing provider configuration must be presented as remediable")
	}
}

func TestInvestigationTransparencyTreatsUnavailableCapabilityAsCollectionGap(t *testing.T) {
	coverage := canonicalIntegrationCoverage{Capabilities: map[string]canonicalCapabilityStatus{
		"actor_history": {
			Capability:  "Actor historical memory",
			Status:      canonicalCapabilityUnavailable,
			Source:      "actor_history",
			Limitations: []string{"Historical memory is unavailable in this runtime."},
		},
	}}
	got := buildInvestigationTransparency(coverage)
	if len(got.CollectionGaps) != 1 || len(got.EvidenceLimits) != 0 {
		t.Fatalf("unexpected transparency split: %#v", got)
	}
}
