package services

import (
	"testing"

	"koschei/api/internal/web3"
)

func TestClassifyProviderWitnessObservationVerifiedQuorum(t *testing.T) {
	court := web3.EvidenceCourtResult{Enabled: true, Status: "verified", ValueHash: "abc"}
	agree := classifyProviderWitnessObservation(court, web3.EvidenceCourtWitness{Status: "observed", ValueHash: "abc"})
	if !agree.Agreement || agree.Disagreement || agree.Conflict {
		t.Fatalf("unexpected agreement observation: %#v", agree)
	}
	disagree := classifyProviderWitnessObservation(court, web3.EvidenceCourtWitness{Status: "observed", ValueHash: "def"})
	if !disagree.Disagreement || disagree.Agreement || disagree.Conflict {
		t.Fatalf("unexpected disagreement observation: %#v", disagree)
	}
}

func TestClassifyProviderWitnessObservationConflictAssignsNoFault(t *testing.T) {
	court := web3.EvidenceCourtResult{Enabled: true, Status: "conflict"}
	observation := classifyProviderWitnessObservation(court, web3.EvidenceCourtWitness{Status: "observed", ValueHash: "abc"})
	if !observation.Conflict || observation.Agreement || observation.Disagreement {
		t.Fatalf("court conflict must not identify a guilty witness: %#v", observation)
	}
}

func TestClassifyProviderWitnessObservationRateLimitIsAvailabilityFailure(t *testing.T) {
	observation := classifyProviderWitnessObservation(
		web3.EvidenceCourtResult{Enabled: true, Status: "insufficient"},
		web3.EvidenceCourtWitness{Status: "unavailable", ErrorClass: "rate_limited"},
	)
	if !observation.Unavailable || !observation.RateLimited || observation.Disagreement {
		t.Fatalf("unexpected rate-limit observation: %#v", observation)
	}
}

func TestDeriveProviderWitnessTrustState(t *testing.T) {
	cases := []struct {
		name string
		row  ProviderWitnessMemory
		want string
	}{
		{name: "learning", row: ProviderWitnessMemory{Observations: 2, QuorumAgreements: 2}, want: "learning"},
		{name: "consistent", row: ProviderWitnessMemory{Observations: 3, QuorumAgreements: 3}, want: "consistent"},
		{name: "availability degraded", row: ProviderWitnessMemory{Observations: 4, QuorumAgreements: 1, UnavailableCount: 3}, want: "availability_degraded"},
		{name: "divergent", row: ProviderWitnessMemory{Observations: 5, QuorumAgreements: 3, QuorumDisagreements: 2}, want: "divergent"},
		{name: "quarantine repeated divergence", row: ProviderWitnessMemory{Observations: 8, QuorumAgreements: 3, QuorumDisagreements: 5}, want: "quarantine_candidate"},
		{name: "quarantine divergence malformed", row: ProviderWitnessMemory{Observations: 8, QuorumAgreements: 4, QuorumDisagreements: 3, MalformedCount: 1}, want: "quarantine_candidate"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := deriveProviderWitnessTrustState(tc.row); got != tc.want {
				t.Fatalf("expected %q, got %q", tc.want, got)
			}
		})
	}
}

func TestProviderWitnessMemoryNeverAutoRemovesProvider(t *testing.T) {
	policy := providerWitnessMemoryPolicy()
	if policy["memory_does_not_auto_remove_provider"] != true {
		t.Fatalf("provider memory must remain advisory until explicit enforcement exists: %#v", policy)
	}
	if policy["numeric_trust_score_disabled"] != true {
		t.Fatalf("numeric provider trust score must stay disabled: %#v", policy)
	}
}
