package services

import (
	"testing"
	"time"
)

func TestCampaignGenomeSnapshotIdentityIgnoresObservationTime(t *testing.T) {
	genome := ActorCampaignGenome{
		Version: ActorCampaignGenomeVersion,
		ActorWallet: "Actor11111111111111111111111111111111111111",
		Network: "solana-mainnet",
		Status: "verified_supported", Complete: true,
		GenomeID: "KCG1-0123456789ABCDEF",
		PatternHashSHA256: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		EvidenceHashSHA256: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		DescriptorCount: 2, VerifiedDescriptorCount: 1, ObservedDescriptorCount: 1,
		VerifiedSignatureBacked: 1,
		Descriptors: []ActorCampaignGenomeDescriptor{
			{Kind: "relation", Value: "created_token", EvidenceStatus: "verified", SignatureBacked: true, GradeEligible: true},
			{Kind: "recurrence", Value: "creator_deployer_multi_token", EvidenceStatus: "observed", GradeEligible: true},
		},
		WatchDescriptors: []ActorCampaignGenomeDescriptor{},
		Policy: map[string]any{"same_genome_is_not_same_person": true},
	}
	first, err := campaignGenomeSnapshotFromGenome(genome, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	second, err := campaignGenomeSnapshotFromGenome(genome, time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC))
	if err != nil {
		t.Fatal(err)
	}
	if first.SnapshotKey != second.SnapshotKey {
		t.Fatalf("snapshot key changed with observation time: %s %s", first.SnapshotKey, second.SnapshotKey)
	}
	if first.RecordHash != second.RecordHash {
		t.Fatalf("record hash changed with observation time: %s %s", first.RecordHash, second.RecordHash)
	}
	if first.ObservedAt.Equal(second.ObservedAt) {
		t.Fatal("observation metadata should remain distinct")
	}
	if len(first.SnapshotKey) != len("KCGS1-")+64 || len(first.RecordHash) != len("sha256:")+64 {
		t.Fatalf("invalid snapshot identity: key=%q hash=%q", first.SnapshotKey, first.RecordHash)
	}
}

func TestCampaignGenomeSnapshotRejectsObservedOnlyGenome(t *testing.T) {
	genome := ActorCampaignGenome{
		Version: ActorCampaignGenomeVersion, ActorWallet: "actor", Network: "solana-mainnet",
		Status: "observed_only", Complete: false,
	}
	if _, err := campaignGenomeSnapshotFromGenome(genome, time.Now().UTC()); err == nil {
		t.Fatal("observed-only genome must not enter persistent genome index")
	}
}

func TestCampaignGenomeMatchReportDoesNotClaimOperatorIdentity(t *testing.T) {
	genome := ActorCampaignGenome{
		Version: ActorCampaignGenomeVersion, ActorWallet: "actor", Network: "solana-mainnet",
		Status: "verified_supported", Complete: true, GenomeID: "KCG1-TEST",
		PatternHashSHA256: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		EvidenceHashSHA256: "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
		VerifiedSignatureBacked: 1,
	}
	out, err := LoadCampaignGenomePatternMatches(t.Context(), nil, genome, 25)
	if err != nil {
		t.Fatal(err)
	}
	if out.Complete || out.Status != "source_unavailable" {
		t.Fatalf("unexpected unavailable report: %+v", out)
	}
	if out.VerdictAuthority || out.SameOperatorClaim || out.RealWorldIdentityClaim || out.WrongdoingClaim {
		t.Fatalf("genome match report acquired prohibited claim authority: %+v", out)
	}
}
