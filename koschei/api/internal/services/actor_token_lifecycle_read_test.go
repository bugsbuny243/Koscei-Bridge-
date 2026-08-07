package services

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestActorLifecycleRecurrencePostgres17(t *testing.T) {
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

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	network := "solana-mainnet"
	observedAt := time.Date(2026, 8, 7, 12, 0, 0, 0, time.UTC)
	store := NewActorDefenseStore(db)

	singleActor := "fixture-single-creator-" + suffix
	singleMint := "fixture-single-mint-" + suffix
	if _, err := store.UpsertTokenLifecycleObservation(ctx, ActorTokenLifecycleInput{
		Network: network, ActorWallet: singleActor, Mint: singleMint,
		CreationSignature: "fixture-single-signature-" + suffix, CreationSlot: 101,
		CreatedOnChainAt: observedAt.Add(-time.Hour), ObservedAt: observedAt, CurrentLiquidityUSD: 10,
	}); err != nil {
		t.Fatal(err)
	}
	single, err := store.LoadTokenLifecycleRecurrence(ctx, singleActor, network, singleMint)
	if err != nil {
		t.Fatal(err)
	}
	if single.TotalTokens != 1 || len(single.OtherMints) != 0 || single.Status != "single_token_only" {
		t.Fatalf("single token became recurrence: %#v", single)
	}

	actor := "fixture-repeat-creator-" + suffix
	mintA := "fixture-lifecycle-a-" + suffix
	mintB := "fixture-lifecycle-b-" + suffix
	for index, input := range []ActorTokenLifecycleInput{
		{Network: network, ActorWallet: actor, Mint: mintA, CreationSignature: "fixture-signature-a-" + suffix, CreationSlot: 201, CreatedOnChainAt: observedAt.Add(-2 * time.Hour), ObservedAt: observedAt, CurrentLiquidityUSD: 10},
		{Network: network, ActorWallet: actor, Mint: mintB, CreationSignature: "fixture-signature-b-" + suffix, CreationSlot: 202, CreatedOnChainAt: observedAt.Add(-3 * time.Hour), ObservedAt: observedAt.Add(time.Minute), CurrentLiquidityUSD: 0},
	} {
		if _, err := store.UpsertTokenLifecycleObservation(ctx, input); err != nil {
			t.Fatalf("upsert %d: %v", index, err)
		}
	}
	recurrence, err := store.LoadTokenLifecycleRecurrence(ctx, actor, network, mintB)
	if err != nil {
		t.Fatal(err)
	}
	if recurrence.TotalTokens != 2 || recurrence.InactiveOrDeadTokens != 1 || recurrence.EvidenceStatus != "verified" || !recurrence.ReferencesComplete {
		t.Fatalf("recurrence=%#v", recurrence)
	}
	if len(recurrence.OtherMints) != 1 || recurrence.OtherMints[0] != mintA {
		t.Fatalf("other mints=%#v", recurrence.OtherMints)
	}

	analysis := ArvisAnalysis{Arms: []SecurityRadarVerdict{{
		Module: "Repeat Actor Scan", ModuleID: ModuleRepeatActorScan, Signals: map[string]any{"evidence_status": "observed_no_repeat_match"}, Evidence: []string{},
	}}}
	analysis = ApplyActorTokenLifecycleRecurrenceToAnalysis(analysis, recurrence)
	if len(analysis.Arms) != 1 || analysis.Arms[0].Signals["evidence_status"] != "verified" || analysis.Arms[0].Signals["creator_token_recurrence"] != true {
		t.Fatalf("repeat actor arm=%#v", analysis.Arms)
	}
}
