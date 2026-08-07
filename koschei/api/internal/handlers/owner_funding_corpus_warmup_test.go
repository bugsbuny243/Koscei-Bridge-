package handlers

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"koschei/api/internal/jobs"

	_ "github.com/lib/pq"
)

type fakeFundingWarmupStore struct {
	seen map[string]jobs.Job
	next int
}

func (f *fakeFundingWarmupStore) CreateUniqueActive(_ context.Context, in jobs.CreateInput, dedupeKey string) (jobs.Job, bool, error) {
	if f.seen == nil {
		f.seen = map[string]jobs.Job{}
	}
	if existing, ok := f.seen[dedupeKey]; ok {
		return existing, false, nil
	}
	f.next++
	job := jobs.Job{ID: "fixture-job-" + in.Target, Type: in.Type, Network: in.Network, Target: in.Target, Status: "queued"}
	f.seen[dedupeKey] = job
	return job, true, nil
}

func TestFundingCorpusWarmupIsCappedAndStableDedupePreventsReenqueue(t *testing.T) {
	candidates := []fundingCorpusWarmupCandidate{
		{Network: "solana-mainnet", Target: "fixture-target-a"},
		{Network: "solana-mainnet", Target: "fixture-target-b"},
		{Network: "solana-mainnet", Target: "fixture-target-c"},
		{Network: "solana-mainnet", Target: "fixture-target-d"},
	}
	store := &fakeFundingWarmupStore{}
	first := enqueueFundingCorpusWarmupCandidates(context.Background(), store, candidates, 2)
	if first.Enqueued != 2 || len(first.JobIDs) != 2 {
		t.Fatalf("first warm-up enqueued=%d jobs=%d want=2/2", first.Enqueued, len(first.JobIDs))
	}
	second := enqueueFundingCorpusWarmupCandidates(context.Background(), store, candidates[:2], 2)
	if second.Enqueued != 0 || second.AlreadyKnown != 2 {
		t.Fatalf("already-warmed targets were re-enqueued: %#v", second)
	}
	if got := normalizedFundingCorpusWarmupLimit(1000); got != fundingCorpusWarmupMaximumLimit {
		t.Fatalf("maximum cap=%d want=%d", got, fundingCorpusWarmupMaximumLimit)
	}
}

func TestFundingCorpusWarmupCompletedJobIsDurableAcrossCallsPostgres17(t *testing.T) {
	databaseURL := os.Getenv("KOSCHEI_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KOSCHEI_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	suffix := time.Now().UTC().Format("20060102150405.000000000")
	candidate := fundingCorpusWarmupCandidate{Network: "solana-mainnet", Target: "fixture-warm-target-" + suffix}
	store := jobs.NewStore(db)
	first := enqueueFundingCorpusWarmupCandidates(ctx, store, []fundingCorpusWarmupCandidate{candidate}, 1)
	if first.Enqueued != 1 || len(first.JobIDs) != 1 {
		t.Fatalf("first durable enqueue=%#v", first)
	}
	if err := store.Complete(ctx, first.JobIDs[0], map[string]any{"fixture": true}); err != nil {
		t.Fatal(err)
	}
	second := enqueueFundingCorpusWarmupCandidates(ctx, store, []fundingCorpusWarmupCandidate{candidate}, 1)
	if second.Enqueued != 0 || second.AlreadyKnown != 1 {
		t.Fatalf("completed warm-up was re-enqueued: %#v", second)
	}
}

func TestFundingCorpusWarmupIntroducesNoLoopTickerOrListen(t *testing.T) {
	raw, err := os.ReadFile("owner_funding_corpus_warmup.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	for _, forbidden := range []string{"go func(", "time.NewTicker(", "LISTEN "} {
		if strings.Contains(source, forbidden) {
			t.Fatalf("warm-up source contains forbidden persistent mechanism %q", forbidden)
		}
	}
	if !strings.Contains(source, "CreateUniqueActive") || !strings.Contains(source, "CanonicalInvestigationJobType") {
		t.Fatal("warm-up does not use the canonical investigation job path")
	}
}
