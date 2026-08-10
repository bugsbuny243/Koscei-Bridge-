package services

import (
	"testing"
	"time"
)

func TestCampaignTempoFingerprintRecurringVerifiedPathsTriggerWatchOnly(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	graph := PersistentFundingTrajectoryGraph{
		Version: PersistentFundingTrajectoryGraphVersion,
		Network: "solana-mainnet", SubjectWallet: "ActorA",
		Available: true, Complete: true, Status: "persistent_trajectory_observed",
		EvidenceHashSHA256: "sha256:tempo-graph",
		Edges: []PersistentFundingTrajectoryEdge{
			tempoEdge("Funder1", "wallet", "ActorA", "wallet", "funding", "funded_actor", "verified", base, "fund-a", nil),
			tempoEdge("ActorA", "wallet", "TokenA", "token", "creation", "created_token", "verified", base.Add(10*time.Minute), "create-a", nil),
			tempoLifecycleEdge("ActorA", "TokenA", base.Add(20*time.Minute), base.Add(50*time.Minute), base.Add(55*time.Minute)),
			tempoEdge("ActorA", "wallet", "TokenA", "token", "exit_event", "liquidity_removal", "verified", base.Add(50*time.Minute), "exit-a", nil),

			tempoEdge("Funder1", "wallet", "ActorB", "wallet", "funding", "funded_actor", "verified", base.Add(2*time.Hour), "fund-b", nil),
			tempoEdge("ActorB", "wallet", "TokenB", "token", "creation", "created_token", "verified", base.Add(12*time.Hour+10*time.Minute), "create-b", nil),
			tempoLifecycleEdge("ActorB", "TokenB", base.Add(12*time.Hour+20*time.Minute), base.Add(12*time.Hour+50*time.Minute), base.Add(12*time.Hour+55*time.Minute)),
			tempoEdge("ActorB", "wallet", "TokenB", "token", "exit_event", "liquidity_removal", "verified", base.Add(12*time.Hour+50*time.Minute), "exit-b", nil),
		},
	}

	tempo := BuildCampaignTempoFingerprint(graph)
	if !tempo.Available || !tempo.Complete || tempo.PathCount != 4 {
		// Each token has two qualifying terminal families: verified lifecycle
		// inactive and verified liquidity-removal exit.
		t.Fatalf("unexpected tempo report: %+v", tempo)
	}
	if tempo.DistinctActorCount != 2 || tempo.DistinctTokenCount != 2 || tempo.DistinctFundingSources != 1 {
		t.Fatalf("unexpected tempo coverage: %+v", tempo)
	}
	if tempo.FingerprintSHA256 == "" {
		t.Fatalf("missing tempo fingerprint")
	}
	if tempo.VerdictAuthority || tempo.SameOperatorClaim || tempo.RealWorldIdentityClaim || tempo.RugClaim || tempo.WrongdoingClaim {
		t.Fatalf("tempo report acquired prohibited authority: %+v", tempo)
	}

	match := behaviorSignatureCampaignTempoRecurrence(tempo)
	if !match.Triggered || match.Status != "observed_watch" || match.EvidenceStatus != "observed" {
		t.Fatalf("expected watch-only tempo recurrence: %+v", match)
	}
	if match.GradeEligible || match.VerdictAuthority {
		t.Fatalf("tempo recurrence acquired grade/verdict authority: %+v", match)
	}
	if len(match.ActorWallets) != 2 || len(match.Targets) != 2 || len(match.FundingSources) != 1 || match.FundingSources[0] != "Funder1" {
		t.Fatalf("unexpected recurrence scope: %+v", match)
	}
	for _, ref := range []string{"fund-a", "create-a", "exit-a", "fund-b", "create-b", "exit-b", graph.EvidenceHashSHA256, tempo.FingerprintSHA256} {
		if !containsBehaviorRef(match.EvidenceRefs, ref) {
			t.Fatalf("missing evidence ref %q in %v", ref, match.EvidenceRefs)
		}
	}
}

func TestCampaignTempoFingerprintRequiresVerifiedCreation(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	graph := PersistentFundingTrajectoryGraph{
		Network: "solana-mainnet", Available: true, Complete: true,
		Edges: []PersistentFundingTrajectoryEdge{
			tempoEdge("Funder1", "wallet", "ActorA", "wallet", "funding", "funded_actor", "verified", base, "fund-a", nil),
			tempoEdge("ActorA", "wallet", "TokenA", "token", "creation", "created_token", "observed", base.Add(10*time.Minute), "create-a", nil),
			tempoLifecycleEdge("ActorA", "TokenA", base.Add(20*time.Minute), base.Add(50*time.Minute), base.Add(55*time.Minute)),
			tempoEdge("ActorA", "wallet", "TokenA", "token", "exit_event", "liquidity_removal", "verified", base.Add(50*time.Minute), "exit-a", nil),
		},
	}
	tempo := BuildCampaignTempoFingerprint(graph)
	if tempo.Available || tempo.PathCount != 0 {
		t.Fatalf("observed-only creation must withhold tempo path: %+v", tempo)
	}
}

func TestCampaignTempoFingerprintRequiresPositiveLiquidityTimestamp(t *testing.T) {
	base := time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)
	graph := PersistentFundingTrajectoryGraph{
		Network: "solana-mainnet", Available: true, Complete: true,
		Edges: []PersistentFundingTrajectoryEdge{
			tempoEdge("Funder1", "wallet", "ActorA", "wallet", "funding", "funded_actor", "verified", base, "fund-a", nil),
			tempoEdge("ActorA", "wallet", "TokenA", "token", "creation", "created_token", "verified", base.Add(10*time.Minute), "create-a", nil),
			tempoEdge("ActorA", "wallet", "TokenA", "token", "exit_event", "creator_sell", "verified", base.Add(50*time.Minute), "exit-a", nil),
		},
	}
	tempo := BuildCampaignTempoFingerprint(graph)
	if tempo.Available || tempo.PathCount != 0 {
		t.Fatalf("missing first-liquidity time must withhold tempo path: %+v", tempo)
	}
}

func TestCampaignTempoBehaviorRequiresDistinctActorAddresses(t *testing.T) {
	tempo := CampaignTempoFingerprintReport{
		Version: CampaignTempoFingerprintVersion, Network: "solana-mainnet", Available: true, Complete: true,
		FingerprintSHA256: "sha256:same-actor",
		Paths: []CampaignTempoPath{
			{FundingSourceWallet: "Funder1", ActorWallet: "ActorA", TokenMint: "TokenA", TerminalFamily: "exit_event:creator_sell", TempoProfile: "exit_event:creator_sell|f2c=5m_30m|c2l=5m_30m|l2t=30m_2h"},
			{FundingSourceWallet: "Funder1", ActorWallet: "ActorA", TokenMint: "TokenB", TerminalFamily: "exit_event:creator_sell", TempoProfile: "exit_event:creator_sell|f2c=5m_30m|c2l=5m_30m|l2t=30m_2h"},
		},
	}
	match := behaviorSignatureCampaignTempoRecurrence(tempo)
	if match.Triggered {
		t.Fatalf("same actor with multiple tokens belongs to exact-address memory, not BEH-007: %+v", match)
	}
}

func TestCampaignTempoDurationBinsAreDeterministic(t *testing.T) {
	cases := []struct {
		seconds int64
		want    string
	}{
		{0, "lt_5m"}, {299, "lt_5m"}, {300, "5m_30m"}, {1799, "5m_30m"},
		{1800, "30m_2h"}, {7199, "30m_2h"}, {7200, "2h_12h"},
		{43200, "12h_48h"}, {172800, "2d_7d"}, {604800, "gte_7d"},
	}
	for _, tc := range cases {
		if got := campaignTempoDurationBin(tc.seconds); got != tc.want {
			t.Fatalf("seconds=%d got=%q want=%q", tc.seconds, got, tc.want)
		}
	}
}

func tempoEdge(source, sourceKind, target, targetKind, evidenceKind, relation, state string, at time.Time, signature string, metadata map[string]any) PersistentFundingTrajectoryEdge {
	if metadata == nil {
		metadata = map[string]any{}
	}
	return PersistentFundingTrajectoryEdge{
		SourceID: source, SourceKind: sourceKind, TargetID: target, TargetKind: targetKind,
		EvidenceKind: evidenceKind, Relation: relation, EvidenceState: state,
		ObservedAt: at.UTC().Format(time.RFC3339Nano), Signature: signature, Metadata: metadata,
	}
}

func tempoLifecycleEdge(actor, token string, firstLiquid, inactiveSince, lastObserved time.Time) PersistentFundingTrajectoryEdge {
	return tempoEdge(actor, "wallet", token, "token", "lifecycle", "lifecycle_inactive_or_dead", "verified", lastObserved, "", map[string]any{
		"first_liquid_observed_at": firstLiquid.UTC().Format(time.RFC3339Nano),
		"current_inactive_since":   inactiveSince.UTC().Format(time.RFC3339Nano),
	})
}
