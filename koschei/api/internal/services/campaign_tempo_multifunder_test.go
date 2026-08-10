package services

import (
	"testing"
	"time"
)

func TestCampaignTempoFingerprintPreservesEachVerifiedFunder(t *testing.T) {
	base := time.Date(2026, 8, 2, 0, 0, 0, 0, time.UTC)
	graph := PersistentFundingTrajectoryGraph{
		Network: "solana-mainnet", SubjectWallet: "ActorA", Available: true, Complete: true,
		EvidenceHashSHA256: "sha256:multi-funder",
		Edges: []PersistentFundingTrajectoryEdge{
			tempoEdge("FunderOld", "wallet", "ActorA", "wallet", "funding", "funded_actor", "verified", base, "fund-old", nil),
			tempoEdge("FunderNew", "wallet", "ActorA", "wallet", "funding", "funded_actor", "verified", base.Add(5*time.Minute), "fund-new", nil),
			tempoEdge("ActorA", "wallet", "TokenA", "token", "creation", "created_token", "verified", base.Add(10*time.Minute), "create-a", nil),
			tempoLifecycleEdge("ActorA", "TokenA", base.Add(20*time.Minute), base.Add(50*time.Minute), base.Add(55*time.Minute)),
			tempoEdge("ActorA", "wallet", "TokenA", "token", "exit_event", "liquidity_removal", "verified", base.Add(50*time.Minute), "exit-a", nil),
		},
	}

	report := BuildCampaignTempoFingerprint(graph)
	if !report.Available || report.DistinctFundingSources != 2 || report.PathCount != 4 {
		t.Fatalf("expected two funders across lifecycle+exit paths: %+v", report)
	}
	funders := map[string]int{}
	for _, path := range report.Paths {
		funders[path.FundingSourceWallet]++
	}
	if funders["FunderOld"] != 2 || funders["FunderNew"] != 2 {
		t.Fatalf("per-funder paths lost: %+v", funders)
	}
}
