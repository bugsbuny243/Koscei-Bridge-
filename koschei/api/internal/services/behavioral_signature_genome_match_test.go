package services

import "testing"

func TestBehavioralSignatureGenomeMatchIsWatchOnly(t *testing.T) {
	genome := ActorCampaignGenome{
		Version: ActorCampaignGenomeVersion, ActorWallet: "CurrentActor", Network: "solana-mainnet",
		Status: "verified_supported", Complete: true, GenomeID: "KCG1-CURRENT",
		PatternHashSHA256:       "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		VerifiedSignatureBacked: 1,
	}
	matches := CampaignGenomeMatchReport{
		Version: CampaignGenomeIndexSchemaVersion, Network: "solana-mainnet", ActorWallet: "CurrentActor",
		GenomeID: genome.GenomeID, PatternHashSHA256: genome.PatternHashSHA256,
		Available: true, Complete: true, Status: "technical_pattern_matches_observed", MatchCount: 2, OtherActorCount: 2,
		Matches: []CampaignGenomePatternMatch{
			{ActorWallet: "OtherActorA", SnapshotKey: "KCGS1-a", RecordHash: "sha256:a"},
			{ActorWallet: "OtherActorB", SnapshotKey: "KCGS1-b", RecordHash: "sha256:b"},
		},
	}
	history := SecurityIncidentCorpusView{Network: "solana-mainnet", ActorWallet: "CurrentActor", Complete: true, Records: []SecurityIncidentCorpusRecord{}}
	funding := FundingClusterOutcomeMemory{Network: "solana-mainnet", Complete: true, Sources: []FundingClusterOutcomeSource{}}

	report := BuildBehavioralSignatureReportWithGenomeMatches(
		"MintCurrent", history, funding, genome, ActorOperationalMemoryReport{}, matches,
	)
	var found *BehavioralSignatureMatch
	for i := range report.Matches {
		if report.Matches[i].SignatureID == "KOSCH-BEH-005" {
			found = &report.Matches[i]
			break
		}
	}
	if found == nil || !found.Triggered {
		t.Fatalf("genome signature missing: %+v", report.Matches)
	}
	if found.Status != "observed_watch" || found.EvidenceStatus != "observed" {
		t.Fatalf("genome match must remain watch-only: %+v", found)
	}
	if found.GradeEligible || found.VerdictAuthority {
		t.Fatalf("genome match acquired prohibited authority: %+v", found)
	}
	if len(found.ActorWallets) != 2 {
		t.Fatalf("matched actors=%v", found.ActorWallets)
	}
	if report.WatchCount != 1 || report.VerifiedSupportedCount != 0 {
		t.Fatalf("counts verified=%d watch=%d", report.VerifiedSupportedCount, report.WatchCount)
	}
}
