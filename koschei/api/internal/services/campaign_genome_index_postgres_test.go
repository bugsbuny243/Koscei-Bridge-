package services

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestCampaignGenomeIndexPostgres17(t *testing.T) {
	databaseURL := os.Getenv("KOSCHEI_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KOSCHEI_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	pattern := "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
	genome := func(actor, evidence, genomeID string) ActorCampaignGenome {
		return ActorCampaignGenome{
			Version: ActorCampaignGenomeVersion, ActorWallet: actor, Network: "solana-mainnet",
			Status: "verified_supported", Complete: true, GenomeID: genomeID,
			PatternHashSHA256: pattern, EvidenceHashSHA256: evidence,
			DescriptorCount: 1, VerifiedDescriptorCount: 1, VerifiedSignatureBacked: 1,
			Descriptors: []ActorCampaignGenomeDescriptor{
				{Kind: "relation", Value: "created_token", EvidenceStatus: "verified", SignatureBacked: true, GradeEligible: true},
			},
			WatchDescriptors: []ActorCampaignGenomeDescriptor{},
			Policy:           map[string]any{"same_genome_is_not_same_person": true},
		}
	}
	firstGenome := genome(
		"GenomeActor11111111111111111111111111111111111",
		"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"KCG1-AAAAAAAAAAAAAAAA",
	)
	secondGenome := genome(
		"GenomeActor22222222222222222222222222222222222",
		"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"KCG1-BBBBBBBBBBBBBBBB",
	)

	first, inserted, err := PersistCampaignGenomeSnapshot(ctx, db, firstGenome)
	if err != nil {
		t.Fatal(err)
	}
	if !inserted || first.ID == "" || first.SnapshotKey == "" || first.RecordHash == "" {
		t.Fatalf("first snapshot=%+v inserted=%v", first, inserted)
	}
	second, inserted, err := PersistCampaignGenomeSnapshot(ctx, db, secondGenome)
	if err != nil {
		t.Fatal(err)
	}
	if !inserted || second.ID == "" {
		t.Fatalf("second snapshot=%+v inserted=%v", second, inserted)
	}

	repeated, inserted, err := PersistCampaignGenomeSnapshot(ctx, db, firstGenome)
	if err != nil {
		t.Fatal(err)
	}
	if inserted {
		t.Fatal("identical evidence snapshot must be idempotent")
	}
	if repeated.SnapshotKey != first.SnapshotKey || repeated.RecordHash != first.RecordHash || !repeated.ObservedAt.Equal(first.ObservedAt) {
		t.Fatalf("repeated snapshot drifted: first=%+v repeated=%+v", first, repeated)
	}

	matches, err := LoadCampaignGenomePatternMatches(ctx, db, firstGenome, 25)
	if err != nil {
		t.Fatal(err)
	}
	if !matches.Complete || !matches.Available || matches.Status != "technical_pattern_matches_observed" || matches.MatchCount != 1 || matches.OtherActorCount != 1 {
		t.Fatalf("match report=%+v", matches)
	}
	if len(matches.Matches) != 1 || matches.Matches[0].ActorWallet != secondGenome.ActorWallet {
		t.Fatalf("matches=%+v", matches.Matches)
	}
	if matches.VerdictAuthority || matches.SameOperatorClaim || matches.RealWorldIdentityClaim || matches.WrongdoingClaim {
		t.Fatalf("pattern match acquired prohibited authority: %+v", matches)
	}

	// Prove append-only semantics without aborting the remainder of the test.
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SAVEPOINT genome_immutable`); err != nil {
		t.Fatal(err)
	}
	if _, err := tx.ExecContext(ctx, `UPDATE security_campaign_genome_index SET genome_id='mutated' WHERE snapshot_key=$1`, first.SnapshotKey); err == nil {
		t.Fatal("campaign genome index update unexpectedly succeeded")
	}
	if _, err := tx.ExecContext(ctx, `ROLLBACK TO SAVEPOINT genome_immutable`); err != nil {
		t.Fatal(err)
	}
}
