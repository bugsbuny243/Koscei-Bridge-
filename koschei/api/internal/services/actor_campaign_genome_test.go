package services

import (
	"strings"
	"testing"
	"time"
)

func TestActorCampaignGenomeMatchesTechnicalPatternAcrossDifferentWallets(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	first := ActorDefenseDossier{
		Wallet:  "WalletAlpha",
		Network: "solana-mainnet",
		Track: ActorDefenseTrack{
			State: "correlated", CreatedTokenCount: 2, RelatedActorCount: 1,
		},
		Evidence: []ActorDefenseEvidenceRecord{
			{
				ActorWallet: "WalletAlpha", CounterpartKind: "wallet", CounterpartID: "CounterpartA",
				Relation: "direct_sol_transfer_out", VerificationStatus: "verified", EvidenceKey: "evidence-alpha-sol",
				Source: "solana_rpc", Signature: "sig-alpha-sol", Slot: 100, ObservedAt: now,
				AmountNative: 1.5, Metadata: map[string]any{"program": "system", "source_wallet": "WalletAlpha", "destination_wallet": "CounterpartA"},
			},
			{
				ActorWallet: "WalletAlpha", CounterpartKind: "pool", CounterpartID: "PoolA",
				Relation: "liquidity_remove_activity", VerificationStatus: "verified", EvidenceKey: "evidence-alpha-liquidity",
				Source: "solana_rpc", Signature: "sig-alpha-liquidity", Slot: 101, ObservedAt: now.Add(time.Second),
				TokenMint: "MintAlpha", TokenAmount: 100, Metadata: map[string]any{"program": "raydium", "source_wallet": "WalletAlpha", "destination_wallet": "PoolA", "actor_role": "liquidity_operator"},
			},
		},
	}
	second := ActorDefenseDossier{
		Wallet:  "WalletBeta",
		Network: "solana-mainnet",
		Track: ActorDefenseTrack{
			State: "correlated", CreatedTokenCount: 2, RelatedActorCount: 1,
		},
		Evidence: []ActorDefenseEvidenceRecord{
			{
				ActorWallet: "WalletBeta", CounterpartKind: "wallet", CounterpartID: "DifferentCounterpart",
				Relation: "direct_sol_transfer_out", VerificationStatus: "verified", EvidenceKey: "evidence-beta-sol",
				Source: "solana_rpc", Signature: "sig-beta-sol", Slot: 200, ObservedAt: now.Add(time.Hour),
				AmountNative: 9.25, Metadata: map[string]any{"program": "system", "source_wallet": "WalletBeta", "destination_wallet": "DifferentCounterpart"},
			},
			{
				ActorWallet: "WalletBeta", CounterpartKind: "pool", CounterpartID: "PoolB",
				Relation: "liquidity_remove_activity", VerificationStatus: "verified", EvidenceKey: "evidence-beta-liquidity",
				Source: "solana_rpc", Signature: "sig-beta-liquidity", Slot: 201, ObservedAt: now.Add(time.Hour + time.Second),
				TokenMint: "DifferentMint", TokenAmount: 999, Metadata: map[string]any{"program": "raydium", "source_wallet": "WalletBeta", "destination_wallet": "PoolB", "actor_role": "liquidity_operator"},
			},
		},
	}

	genomeA := BuildActorCampaignGenome(first)
	genomeB := BuildActorCampaignGenome(second)
	if !genomeA.Complete || !genomeB.Complete || genomeA.Status != "verified_supported" || genomeB.Status != "verified_supported" {
		t.Fatalf("genomes not complete: A=%#v B=%#v", genomeA, genomeB)
	}
	if genomeA.GenomeID == "" || genomeA.GenomeID != genomeB.GenomeID || genomeA.PatternHashSHA256 != genomeB.PatternHashSHA256 {
		t.Fatalf("technical pattern mismatch: A=%#v B=%#v", genomeA, genomeB)
	}
	if genomeA.EvidenceHashSHA256 == genomeB.EvidenceHashSHA256 {
		t.Fatal("wallet-specific evidence hash unexpectedly matched across different evidence")
	}
	if !strings.HasPrefix(genomeA.GenomeID, "KCG1-") {
		t.Fatalf("genome id=%q", genomeA.GenomeID)
	}
	if genomeA.Policy["same_genome_is_not_same_person"] != true || genomeA.Policy["identity_or_wrongdoing_claim"] != false {
		t.Fatalf("unsafe policy=%#v", genomeA.Policy)
	}
}

func TestActorCampaignGenomeObservedOnlyDoesNotIssueGenomeID(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	dossier := ActorDefenseDossier{
		Wallet: "WalletObserved", Network: "solana-mainnet",
		Evidence: []ActorDefenseEvidenceRecord{{
			ActorWallet: "WalletObserved", CounterpartKind: "wallet", CounterpartID: "Counterpart",
			Relation: "direct_sol_transfer_out", VerificationStatus: "observed", EvidenceKey: "observed-evidence",
			Source: "solana_rpc", Signature: "observed-signature", Slot: 100, ObservedAt: now,
			AmountNative: 2, Metadata: map[string]any{"program": "system", "source_wallet": "WalletObserved", "destination_wallet": "Counterpart"},
		}},
	}
	genome := BuildActorCampaignGenome(dossier)
	if genome.Complete || genome.GenomeID != "" || genome.PatternHashSHA256 != "" || genome.Status != "observed_only" {
		t.Fatalf("genome=%#v", genome)
	}
	if genome.VerifiedSignatureBacked != 0 || genome.ObservedDescriptorCount < 2 {
		t.Fatalf("unexpected descriptor counts: %#v", genome)
	}
}

func TestActorCampaignGenomeIncompleteVerifiedLineIsWatchOnly(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	dossier := ActorDefenseDossier{
		Wallet: "WalletIncomplete", Network: "solana-mainnet",
		Evidence: []ActorDefenseEvidenceRecord{{
			ActorWallet: "WalletIncomplete", CounterpartKind: "pool", CounterpartID: "Pool",
			Relation: "liquidity_remove_activity", VerificationStatus: "verified", EvidenceKey: "incomplete-verified",
			Source: "solana_rpc", Signature: "sig", Slot: 123, ObservedAt: now,
			TokenMint: "Mint", TokenAmount: 50,
			Metadata: map[string]any{"actor_role": "liquidity_operator"},
		}},
	}
	genome := BuildActorCampaignGenome(dossier)
	if genome.Complete || genome.GenomeID != "" || genome.VerifiedSignatureBacked != 0 {
		t.Fatalf("incomplete verified evidence issued genome: %#v", genome)
	}
	if genome.WatchDescriptorCount == 0 {
		t.Fatalf("incomplete evidence not retained as watch descriptors: %#v", genome)
	}
	for _, descriptor := range genome.WatchDescriptors {
		if descriptor.SignatureBacked || descriptor.GradeEligible || descriptor.VerificationWeight != "watch_only" {
			t.Fatalf("unsafe watch descriptor=%#v", descriptor)
		}
	}
}

func TestActorCampaignGenomeDustAndInferredStayWatchOnlyAndUnverifiedExcluded(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	dossier := ActorDefenseDossier{
		Wallet: "WalletWatch", Network: "solana-mainnet",
		Evidence: []ActorDefenseEvidenceRecord{
			{
				ActorWallet: "WalletWatch", CounterpartKind: "wallet", CounterpartID: "DustSender",
				Relation: "direct_sol_transfer_in", VerificationStatus: "observed", EvidenceKey: "dust",
				Source: "solana_rpc", Signature: "dust-sig", Slot: 10, ObservedAt: now,
				AmountNative: ActorPossibleDustNativeSOLMax, Metadata: map[string]any{"program": "system", "source_wallet": "DustSender", "destination_wallet": "WalletWatch"},
			},
			{
				ActorWallet: "WalletWatch", CounterpartKind: "service", CounterpartID: "ObservedService",
				Relation: "external_funding_attribution", VerificationStatus: "inferred", EvidenceKey: "inferred",
				Source: "provider", ObservedAt: now,
				Metadata: map[string]any{"program": "provider_attribution", "source_wallet": "ObservedService", "destination_wallet": "WalletWatch"},
			},
			{
				ActorWallet: "WalletWatch", CounterpartKind: "wallet", CounterpartID: "Unknown",
				Relation: "direct_sol_transfer_out", VerificationStatus: "unverified", EvidenceKey: "unverified",
				Source: "unknown", ObservedAt: now,
			},
		},
	}
	genome := BuildActorCampaignGenome(dossier)
	if genome.Complete || genome.GenomeID != "" || genome.DescriptorCount != 0 {
		t.Fatalf("watch-only evidence entered active genome: %#v", genome)
	}
	if genome.WatchDescriptorCount == 0 || genome.ExcludedUnverifiedEvidence != 1 {
		t.Fatalf("watch/excluded counts invalid: %#v", genome)
	}
}

func TestActorCampaignGenomeDeterministicAcrossEvidenceOrder(t *testing.T) {
	now := time.Date(2026, 8, 9, 12, 0, 0, 0, time.UTC)
	a := ActorDefenseEvidenceRecord{
		ActorWallet: "Wallet", CounterpartKind: "wallet", CounterpartID: "A",
		Relation: "direct_sol_transfer_out", VerificationStatus: "verified", EvidenceKey: "a",
		Source: "rpc", Signature: "sig-a", Slot: 1, ObservedAt: now, AmountNative: 1,
		Metadata: map[string]any{"program": "system", "source_wallet": "Wallet", "destination_wallet": "A"},
	}
	b := ActorDefenseEvidenceRecord{
		ActorWallet: "Wallet", CounterpartKind: "pool", CounterpartID: "B",
		Relation: "liquidity_remove_activity", VerificationStatus: "verified", EvidenceKey: "b",
		Source: "rpc", Signature: "sig-b", Slot: 2, ObservedAt: now.Add(time.Second), TokenMint: "Mint", TokenAmount: 1,
		Metadata: map[string]any{"program": "raydium", "source_wallet": "Wallet", "destination_wallet": "B", "actor_role": "liquidity_operator"},
	}
	first := BuildActorCampaignGenome(ActorDefenseDossier{Wallet: "Wallet", Network: "solana-mainnet", Evidence: []ActorDefenseEvidenceRecord{a, b}})
	second := BuildActorCampaignGenome(ActorDefenseDossier{Wallet: "Wallet", Network: "solana-mainnet", Evidence: []ActorDefenseEvidenceRecord{b, a}})
	if first.GenomeID != second.GenomeID || first.PatternHashSHA256 != second.PatternHashSHA256 || first.EvidenceHashSHA256 != second.EvidenceHashSHA256 {
		t.Fatalf("non-deterministic genome: first=%#v second=%#v", first, second)
	}
}
