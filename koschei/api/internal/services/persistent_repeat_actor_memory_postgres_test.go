package services

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// ACTOR_INVESTIGATION_ENGINE.md sections 1, 2 and 6.
// Actor ruleset v1.0; unified Radar ruleset v1.0.
// This test proves repeat-holder intelligence is read from durable actor memory,
// not reconstructed from the legacy 30-day holder snapshot window.
func TestPersistentRepeatActorMemoryPostgres17(t *testing.T) {
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

	const (
		owner = "ci-persistent-repeat-owner"
		mintA = "ci-persistent-repeat-mint-a"
		mintB = "ci-persistent-repeat-mint-b"
	)
	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM security_actor_evidence WHERE network='solana-mainnet' AND actor_wallet=$1`, owner)
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM security_radar_holder_snapshots WHERE network='solana-mainnet' AND owner_wallet=$1`, owner)
	}
	cleanup()
	defer cleanup()

	// Both observations are intentionally older than the legacy 30-day window.
	// No security_radar_holder_snapshots rows are inserted at all.
	_, err = db.ExecContext(ctx, `
		INSERT INTO security_actor_evidence (
			network,actor_wallet,actor_role,counterpart_kind,counterpart_id,relation,
			verification_status,evidence_key,source,observed_at,first_observed_at,last_observed_at,
			program,token_mint,metadata
		) VALUES
		('solana-mainnet',$1,'dominant_holder','token',$2,'dominant_holder_of','observed','ci-holder-a','ci-persistent-memory',TIMESTAMPTZ '2025-01-01 00:00:00+00',TIMESTAMPTZ '2025-01-01 00:00:00+00',TIMESTAMPTZ '2025-01-01 00:00:00+00','spl-token',$2,'{"max_holder_percentage":41.25,"best_holder_rank":2,"persistent_actor_index":true}'::jsonb),
		('solana-mainnet',$1,'dominant_holder','token',$3,'dominant_holder_of','observed','ci-holder-b','ci-persistent-memory',TIMESTAMPTZ '2025-02-01 00:00:00+00',TIMESTAMPTZ '2025-02-01 00:00:00+00',TIMESTAMPTZ '2025-02-01 00:00:00+00','spl-token',$3,'{"max_holder_percentage":63.5,"best_holder_rank":1,"persistent_actor_index":true}'::jsonb)
	`, owner, mintA, mintB)
	if err != nil {
		t.Fatal(err)
	}

	var legacyRows int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM security_radar_holder_snapshots
		WHERE network='solana-mainnet' AND owner_wallet=$1
		  AND scanned_at >= now() - interval '30 days'`, owner).Scan(&legacyRows); err != nil {
		t.Fatal(err)
	}
	if legacyRows != 0 {
		t.Fatalf("legacy 30-day snapshot unexpectedly contains %d row(s)", legacyRows)
	}

	store := NewSecurityRadarStore(db)
	matches, err := store.persistentRepeatDominantHolderMatches(ctx, owner, "solana-mainnet")
	if err != nil {
		t.Fatal(err)
	}
	if len(matches) != 2 {
		t.Fatalf("persistent matches=%#v", matches)
	}
	seen := map[string]bool{}
	for _, match := range matches {
		seen[match.Mint] = true
	}
	if !seen[mintA] || !seen[mintB] {
		t.Fatalf("persistent actor memory lost historical mint relation: %#v", matches)
	}
}
