package services

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestFundingClusterObservationRejectsSingleton(t *testing.T) {
	analysis := HolderClusterAnalysis{
		SharedFundingGroups: []HolderClusterGroup{
			{Key: "fixture-funder", Wallets: []string{"fixture-wallet-a"}, MemberCount: 1, HolderPercentage: 12},
		},
	}
	if got := fundingClusterObservations(analysis); len(got) != 0 {
		t.Fatalf("singleton group produced %d persistent observations", len(got))
	}
}

func TestFundingClusterCorpusPostgres17(t *testing.T) {
	databaseURL := os.Getenv("KOSCHEI_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KOSCHEI_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(2)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	// These identifiers are isolated test fixtures inside the ephemeral CI
	// Postgres service. Production persistence never manufactures replacements
	// for missing wallet, target, slot or amount evidence.
	suffix := time.Now().UTC().Format("20060102150405.000000000")
	funder := "fixture-funder-" + suffix
	targetA := "fixture-target-a-" + suffix
	targetB := "fixture-target-b-" + suffix
	targetSingleton := "fixture-target-singleton-" + suffix
	network := "solana-mainnet"
	analysis := HolderClusterAnalysis{
		SharedFundingGroups: []HolderClusterGroup{
			{
				Key: funder, Wallets: []string{"fixture-member-a-" + suffix, "fixture-member-b-" + suffix},
				MemberCount: 2, HolderPercentage: 31.25,
			},
		},
		Wallets: []HolderClusterWallet{
			{Wallet: "fixture-member-a-" + suffix, AcquisitionSlot: 100},
			{Wallet: "fixture-member-b-" + suffix, AcquisitionSlot: 104},
		},
	}
	store := NewSecurityRadarStore(db)

	if err := store.CaptureFundingClusters(ctx, targetA, network, analysis); err != nil {
		t.Fatal(err)
	}
	var firstObservedAt, firstLastObservedAt time.Time
	var observationCount int
	if err := db.QueryRowContext(ctx, `
		SELECT first_observed_at,last_observed_at,observation_count
		FROM security_funding_clusters
		WHERE funding_source=$1 AND cluster_kind='shared_funder' AND target=$2 AND network=$3`,
		funder, targetA, network).Scan(&firstObservedAt, &firstLastObservedAt, &observationCount); err != nil {
		t.Fatal(err)
	}
	if observationCount != 1 {
		t.Fatalf("initial observation_count=%d want=1", observationCount)
	}

	time.Sleep(5 * time.Millisecond)
	if err := store.CaptureFundingClusters(ctx, targetA, network, analysis); err != nil {
		t.Fatal(err)
	}
	var rowCount, secondObservationCount int
	var secondFirstObservedAt, secondLastObservedAt time.Time
	if err := db.QueryRowContext(ctx, `
		SELECT count(*),min(first_observed_at),max(last_observed_at),max(observation_count)
		FROM security_funding_clusters
		WHERE funding_source=$1 AND cluster_kind='shared_funder' AND target=$2 AND network=$3`,
		funder, targetA, network).Scan(&rowCount, &secondFirstObservedAt, &secondLastObservedAt, &secondObservationCount); err != nil {
		t.Fatal(err)
	}
	if rowCount != 1 || secondObservationCount != 2 {
		t.Fatalf("same scan rerun rows=%d observation_count=%d want 1/2", rowCount, secondObservationCount)
	}
	if !secondFirstObservedAt.Equal(firstObservedAt) {
		t.Fatalf("first_observed_at moved: first=%s second=%s", firstObservedAt, secondFirstObservedAt)
	}
	if !secondLastObservedAt.After(firstLastObservedAt) {
		t.Fatalf("last_observed_at did not move forward: first=%s second=%s", firstLastObservedAt, secondLastObservedAt)
	}

	if err := store.CaptureFundingClusters(ctx, targetB, network, analysis); err != nil {
		t.Fatal(err)
	}
	var distinctTargets int
	if err := db.QueryRowContext(ctx, `
		SELECT distinct_targets
		FROM security_funding_cluster_actors
		WHERE funding_source=$1 AND network=$2`, funder, network).Scan(&distinctTargets); err != nil {
		t.Fatal(err)
	}
	if distinctTargets != 2 {
		t.Fatalf("distinct_targets=%d want=2", distinctTargets)
	}

	recurrence, err := store.LoadFundingRecurrence(ctx, targetB, network, analysis)
	if err != nil {
		t.Fatal(err)
	}
	if recurrence.EvidenceStatus != "verified" || len(recurrence.Sources) != 1 {
		t.Fatalf("recurrence=%#v", recurrence)
	}
	if recurrence.Sources[0].DistinctTargets != 2 || len(recurrence.Sources[0].OtherTargets) != 1 || recurrence.Sources[0].OtherTargets[0] != targetA {
		t.Fatalf("source recurrence=%#v", recurrence.Sources[0])
	}

	singleton := HolderClusterAnalysis{SharedFundingGroups: []HolderClusterGroup{
		{Key: "fixture-singleton-funder-" + suffix, Wallets: []string{"fixture-only-member-" + suffix}, MemberCount: 1},
	}}
	if err := store.CaptureFundingClusters(ctx, targetSingleton, network, singleton); err != nil {
		t.Fatal(err)
	}
	var singletonRows int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM security_funding_clusters WHERE target=$1 AND network=$2`, targetSingleton, network).Scan(&singletonRows); err != nil {
		t.Fatal(err)
	}
	if singletonRows != 0 {
		t.Fatalf("singleton group persisted %d row(s)", singletonRows)
	}
}
