package handlers

import (
	"strings"
	"testing"
	"time"
)

func TestTransactionGuardActorMemoryCandidatesIncludeAuthorityAndTokenOwners(t *testing.T) {
	const (
		wallet = "7YWHMfk9JZe0LM2B9S1yXWBHLDvTw3pAUJ2g7MzoFj3d"
		owner  = "HHPpU9u56Bwxov12nf7DXUCuv6h1q5j1xgGS3yukpump"
		delegate = "yHCxqFDSWNSVQpBmx6GBbMUAZrxD7VuXPWgqvha6PRe"
	)
	decoded := transactionGuardDecodedTransaction{
		TokenOperations: []transactionGuardDecodedTokenOperation{{Kind: "approve", Delegate: delegate, Authority: owner}},
		AutomaticBalance: transactionGuardAutomaticBalanceAnalysis{Accounts: []transactionGuardAutomaticBalanceDelta{{PreTokenOwner: owner, PostTokenOwner: owner}}},
	}
	candidates := transactionGuardActorMemoryCandidates(decoded, wallet)
	roles := map[string][]string{}
	for _, candidate := range candidates {
		roles[candidate.Address] = candidate.Roles
	}
	if !containsGuardString(roles[owner], "token_authority") || !containsGuardString(roles[owner], "pre_token_owner") || !containsGuardString(roles[owner], "post_token_owner") {
		t.Fatalf("owner roles=%#v", roles[owner])
	}
	if !containsGuardString(roles[delegate], "token_delegate") {
		t.Fatalf("delegate roles=%#v", roles[delegate])
	}
}

func TestAggregateTransactionGuardActorMemoryGraphPreservesEvidenceStatusWithoutVerdictAuthority(t *testing.T) {
	const address = "HHPpU9u56Bwxov12nf7DXUCuv6h1q5j1xgGS3yukpump"
	graph := transactionGuardActorMemoryGraph{
		Version: transactionGuardActorMemoryGraphVersion, Network: "solana-mainnet", Complete: true,
		Status: "complete_no_matches", SubjectsChecked: 1, Subjects: []transactionGuardActorMemorySubject{},
		VerdictAuthority: false, RealWorldIdentityClaim: false, SafetyClaim: false,
	}
	candidates := []transactionGuardThreatCandidate{{Address: address, Roles: []string{"token_delegate"}}}
	rows := []transactionGuardActorMemoryRow{
		{Address: address, ActorRole: "dominant_holder", Relation: "dominant_holder_of", VerificationStatus: "observed", TokenMint: "MintA", LastObservedAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)},
		{Address: address, ActorRole: "creator", Relation: "created_token", VerificationStatus: "verified", TokenMint: "MintB", Signature: "sig-1", Slot: 123, LastObservedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)},
	}
	got := aggregateTransactionGuardActorMemoryGraph(graph, candidates, rows)
	if got.SubjectsMatched != 1 || got.VerifiedEvidenceCount != 1 || got.ObservedEvidenceCount != 1 {
		t.Fatalf("graph=%#v", got)
	}
	if got.VerdictAuthority || got.RealWorldIdentityClaim || got.SafetyClaim {
		t.Fatalf("actor memory gained forbidden authority: %#v", got)
	}
	if len(got.Subjects) != 1 || got.Subjects[0].VerifiedCount != 1 || got.Subjects[0].ObservedCount != 1 {
		t.Fatalf("subject=%#v", got.Subjects)
	}
}

func TestUnavailableActorMemoryGraphMakesNoSafetyClaim(t *testing.T) {
	graph := unavailableTransactionGuardActorMemoryGraph(transactionGuardActorMemoryGraph{
		Version: transactionGuardActorMemoryGraphVersion, Network: "solana-mainnet", Complete: true,
		Subjects: []transactionGuardActorMemorySubject{}, Limitations: []string{},
	}, "database unavailable")
	if graph.Complete || graph.Status != "source_unavailable" || graph.SafetyClaim || graph.VerdictAuthority {
		t.Fatalf("graph=%#v", graph)
	}
	if !strings.Contains(strings.Join(graph.Limitations, " "), "does not imply safety or risk") {
		t.Fatalf("limitations=%#v", graph.Limitations)
	}
}
