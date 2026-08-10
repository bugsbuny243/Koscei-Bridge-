package services

import "testing"

func TestBehavioralSignatureTrajectoryRecurrenceIsWatchOnly(t *testing.T) {
	graph := PersistentFundingTrajectoryGraph{
		Version: PersistentFundingTrajectoryGraphVersion,
		Network: "solana-mainnet", SubjectWallet: "ActorA",
		Available: true, Complete: true, Status: "persistent_trajectory_observed",
		EvidenceHashSHA256: "sha256:trajectory-recurrence-fixture",
		Edges: []PersistentFundingTrajectoryEdge{
			{SourceID: "Funder1", SourceKind: "wallet", TargetID: "ActorA", TargetKind: "wallet", Relation: "funded_actor", EvidenceKind: "funding", EvidenceState: "verified", Signature: "fund-a"},
			{SourceID: "Funder1", SourceKind: "wallet", TargetID: "ActorB", TargetKind: "wallet", Relation: "funded_actor", EvidenceKind: "funding", EvidenceState: "verified", Signature: "fund-b"},
			{SourceID: "ActorA", SourceKind: "wallet", TargetID: "TokenA", TargetKind: "token", Relation: "created_token", EvidenceKind: "creation", EvidenceState: "verified", Signature: "create-a"},
			{SourceID: "ActorB", SourceKind: "wallet", TargetID: "TokenB", TargetKind: "token", Relation: "created_token", EvidenceKind: "creation", EvidenceState: "observed", Signature: "create-b"},
			{SourceID: "ActorA", SourceKind: "wallet", TargetID: "TokenA", TargetKind: "token", Relation: "liquidity_removal", EvidenceKind: "exit_event", EvidenceState: "verified", Signature: "exit-a"},
			{SourceID: "ActorB", SourceKind: "wallet", TargetID: "TokenB", TargetKind: "token", Relation: "liquidity_removal", EvidenceKind: "exit_event", EvidenceState: "verified", Signature: "exit-b"},
		},
	}

	report := BuildBehavioralSignatureReportWithTrajectory(
		"CurrentToken",
		SecurityIncidentCorpusView{Network: "solana-mainnet", ActorWallet: "ActorA", Complete: true, Records: []SecurityIncidentCorpusRecord{}},
		FundingClusterOutcomeMemory{Network: "solana-mainnet", Complete: true, Sources: []FundingClusterOutcomeSource{}},
		ActorCampaignGenome{Network: "solana-mainnet", ActorWallet: "ActorA", Complete: false},
		ActorOperationalMemoryReport{},
		CampaignGenomeMatchReport{},
		graph,
	)
	if report.Version != BehavioralSignatureTrajectoryVersion {
		t.Fatalf("version=%q", report.Version)
	}
	var found *BehavioralSignatureMatch
	for i := range report.Matches {
		if report.Matches[i].SignatureID == BehavioralSignatureTrajectoryID {
			found = &report.Matches[i]
			break
		}
	}
	if found == nil || !found.Triggered {
		t.Fatalf("trajectory signature missing: %+v", report.Matches)
	}
	if found.Status != "observed_watch" || found.EvidenceStatus != "observed" {
		t.Fatalf("cross-wallet trajectory recurrence must remain watch-only: %+v", found)
	}
	if found.GradeEligible || found.VerdictAuthority {
		t.Fatalf("trajectory recurrence acquired prohibited authority: %+v", found)
	}
	if len(found.FundingSources) != 1 || found.FundingSources[0] != "Funder1" {
		t.Fatalf("funders=%v", found.FundingSources)
	}
	if len(found.ActorWallets) != 2 || found.ActorWallets[0] != "ActorA" || found.ActorWallets[1] != "ActorB" {
		t.Fatalf("actors=%v", found.ActorWallets)
	}
	if len(found.Targets) != 2 || found.Targets[0] != "TokenA" || found.Targets[1] != "TokenB" {
		t.Fatalf("targets=%v", found.Targets)
	}
	for _, want := range []string{"fund-a", "fund-b", "create-a", "create-b", "exit-a", "exit-b", graph.EvidenceHashSHA256} {
		if !containsBehaviorRef(found.EvidenceRefs, want) {
			t.Fatalf("missing evidence ref %q in %v", want, found.EvidenceRefs)
		}
	}
	if report.WatchCount != 1 || report.VerifiedSupportedCount != 0 || report.TriggeredCount != 1 {
		t.Fatalf("counts triggered=%d verified=%d watch=%d", report.TriggeredCount, report.VerifiedSupportedCount, report.WatchCount)
	}
	if report.Policy["funding_trajectory_recurrence_is_watch_only"] != true {
		t.Fatalf("trajectory policy missing: %+v", report.Policy)
	}
}

func TestBehavioralSignatureTrajectoryRecurrenceRequiresVerifiedFundingForEachActor(t *testing.T) {
	graph := PersistentFundingTrajectoryGraph{
		Network: "solana-mainnet", Available: true, Complete: true, Status: "persistent_trajectory_observed",
		Edges: []PersistentFundingTrajectoryEdge{
			{SourceID: "Funder1", SourceKind: "wallet", TargetID: "ActorA", TargetKind: "wallet", EvidenceKind: "funding", EvidenceState: "verified"},
			{SourceID: "Funder1", SourceKind: "wallet", TargetID: "ActorB", TargetKind: "wallet", EvidenceKind: "funding", EvidenceState: "observed"},
			{SourceID: "ActorA", SourceKind: "wallet", TargetID: "TokenA", TargetKind: "token", EvidenceKind: "creation", EvidenceState: "verified"},
			{SourceID: "ActorB", SourceKind: "wallet", TargetID: "TokenB", TargetKind: "token", EvidenceKind: "creation", EvidenceState: "verified"},
			{SourceID: "ActorA", SourceKind: "wallet", TargetID: "TokenA", TargetKind: "token", Relation: "creator_sell", EvidenceKind: "exit_event", EvidenceState: "verified", Signature: "exit-a"},
			{SourceID: "ActorB", SourceKind: "wallet", TargetID: "TokenB", TargetKind: "token", Relation: "creator_sell", EvidenceKind: "exit_event", EvidenceState: "verified", Signature: "exit-b"},
		},
	}
	match := behaviorSignatureFundingTrajectoryRecurrence(graph)
	if match.Triggered {
		t.Fatalf("observed-only funding path must not trigger cross-wallet recurrence: %+v", match)
	}
}

func TestBehavioralSignatureTrajectoryRecurrenceRequiresDistinctActorAddresses(t *testing.T) {
	graph := PersistentFundingTrajectoryGraph{
		Network: "solana-mainnet", Available: true, Complete: true, Status: "persistent_trajectory_observed",
		Edges: []PersistentFundingTrajectoryEdge{
			{SourceID: "Funder1", SourceKind: "wallet", TargetID: "ActorA", TargetKind: "wallet", EvidenceKind: "funding", EvidenceState: "verified"},
			{SourceID: "ActorA", SourceKind: "wallet", TargetID: "TokenA", TargetKind: "token", EvidenceKind: "creation", EvidenceState: "verified"},
			{SourceID: "ActorA", SourceKind: "wallet", TargetID: "TokenB", TargetKind: "token", EvidenceKind: "creation", EvidenceState: "verified"},
			{SourceID: "ActorA", SourceKind: "wallet", TargetID: "TokenA", TargetKind: "token", Relation: "liquidity_removal", EvidenceKind: "exit_event", EvidenceState: "verified"},
			{SourceID: "ActorA", SourceKind: "wallet", TargetID: "TokenB", TargetKind: "token", Relation: "liquidity_removal", EvidenceKind: "exit_event", EvidenceState: "verified"},
		},
	}
	match := behaviorSignatureFundingTrajectoryRecurrence(graph)
	if match.Triggered {
		t.Fatalf("single-address recurrence belongs to exact-actor memory, not BEH-006: %+v", match)
	}
}

func TestBehavioralSignatureTrajectoryVerifiedInactiveLifecycleRemainsNonRugWatch(t *testing.T) {
	graph := PersistentFundingTrajectoryGraph{
		Network: "solana-mainnet", Available: true, Complete: true, Status: "persistent_trajectory_observed",
		EvidenceHashSHA256: "sha256:lifecycle-fixture",
		Edges: []PersistentFundingTrajectoryEdge{
			{SourceID: "Funder1", SourceKind: "wallet", TargetID: "ActorA", TargetKind: "wallet", EvidenceKind: "funding", EvidenceState: "verified"},
			{SourceID: "Funder1", SourceKind: "wallet", TargetID: "ActorB", TargetKind: "wallet", EvidenceKind: "funding", EvidenceState: "verified"},
			{SourceID: "ActorA", SourceKind: "wallet", TargetID: "TokenA", TargetKind: "token", EvidenceKind: "creation", EvidenceState: "verified"},
			{SourceID: "ActorB", SourceKind: "wallet", TargetID: "TokenB", TargetKind: "token", EvidenceKind: "creation", EvidenceState: "verified"},
			{SourceID: "ActorA", SourceKind: "wallet", TargetID: "TokenA", TargetKind: "token", Relation: "lifecycle_inactive_or_dead", EvidenceKind: "lifecycle", EvidenceState: "verified"},
			{SourceID: "ActorB", SourceKind: "wallet", TargetID: "TokenB", TargetKind: "token", Relation: "lifecycle_inactive_or_dead", EvidenceKind: "lifecycle", EvidenceState: "verified"},
		},
	}
	match := behaviorSignatureFundingTrajectoryRecurrence(graph)
	if !match.Triggered || match.Status != "observed_watch" || match.GradeEligible || match.VerdictAuthority {
		t.Fatalf("verified lifecycle recurrence must remain non-authoritative watch context: %+v", match)
	}
	if len(match.EvidenceRefs) != 1 || match.EvidenceRefs[0] != graph.EvidenceHashSHA256 {
		t.Fatalf("lifecycle recurrence must use graph hash rather than mislabel creation signatures as lifecycle proof: %v", match.EvidenceRefs)
	}
}

func containsBehaviorRef(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
