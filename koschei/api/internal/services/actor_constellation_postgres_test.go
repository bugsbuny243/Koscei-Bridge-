package services

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

// ACTOR_INVESTIGATION_ENGINE.md sections 1 (questions 7, 9 and 10), 3, 4 and 6.
// Actor ruleset v1.0; unified Radar ruleset v1.0.
func TestActorConstellationBidirectionalEvidencePostgres17(t *testing.T) {
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
		walletA = "ci-constellation-wallet-a"
		walletB = "ci-constellation-wallet-b"
		sig     = "ci-constellation-signature-ab"
	)
	cleanup := func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `
			DELETE FROM security_actor_evidence
			WHERE network='solana-mainnet'
			  AND (actor_wallet IN ($1,$2) OR counterpart_id IN ($1,$2))
		`, walletA, walletB)
	}
	cleanup()
	defer cleanup()

	_, err = db.ExecContext(ctx, `
		INSERT INTO security_actor_evidence (
			network,actor_wallet,actor_role,counterpart_kind,counterpart_id,relation,
			verification_status,evidence_key,source,signature,slot,observed_at,
			first_observed_at,last_observed_at,source_wallet,destination_wallet,
			program,amount_native,metadata
		) VALUES (
			'solana-mainnet',$1,'actor','wallet',$2,'direct_sol_transfer_out',
			'verified','ci-constellation-ab','ci-constellation-test',$3,424242,
			TIMESTAMPTZ '2026-08-13 00:00:00+00',TIMESTAMPTZ '2026-08-13 00:00:00+00',TIMESTAMPTZ '2026-08-13 00:00:00+00',
			$1,$2,'system',1.25,'{"actor_signed":true,"persistent_actor_index":true}'::jsonb
		)
	`, walletA, walletB, sig)
	if err != nil {
		t.Fatal(err)
	}

	store := NewActorDefenseStore(db)
	lookup, err := store.loadBoundedActorConstellationCandidates(ctx, walletB, "solana-mainnet", 8)
	if err != nil {
		t.Fatal(err)
	}
	if len(lookup.Candidates) != 1 {
		t.Fatalf("reverse seed should resolve stored A->B evidence, candidates=%#v", lookup.Candidates)
	}
	candidate := lookup.Candidates[0]
	if candidate.Match.Wallet != walletA || candidate.Match.Classification != "verified_counterparty_link" || candidate.Match.EvidenceStatus != "verified" {
		t.Fatalf("unexpected reverse candidate: %#v", candidate.Match)
	}
	if len(candidate.Evidence) == 0 {
		t.Fatal("verified constellation candidate must retain serious evidence rows")
	}
	row := candidate.Evidence[0]
	if row.Signature != sig || row.Slot != 424242 || row.SourceWallet != walletA || row.DestinationWallet != walletB || row.Amount != "1.25" || row.Program != "system" || row.VerificationStatus != "verified" {
		t.Fatalf("evidence row lost canonical serious-claim fields: %#v", row)
	}

	report, err := store.LoadActorConstellation(ctx, walletB, "solana-mainnet", 1, 8, 25)
	if err != nil {
		t.Fatal(err)
	}
	if report.NodeCount != 2 || report.EdgeCount != 1 {
		t.Fatalf("unexpected reverse constellation: %#v", report)
	}
	if len(report.Edges[0].Evidence) == 0 || report.Edges[0].Evidence[0].Signature != sig {
		t.Fatalf("constellation edge must expose resolvable signed evidence: %#v", report.Edges[0])
	}
}
