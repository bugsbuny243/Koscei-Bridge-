package services

import (
	"context"
	"database/sql"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestRetentionArchiveDeletePostgres17(t *testing.T) {
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

	const sourceTable = "ci_retention_source"
	if _, err := db.ExecContext(ctx, `DROP TABLE IF EXISTS ci_retention_source`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.ExecContext(ctx, `
		CREATE TABLE ci_retention_source (
			id uuid PRIMARY KEY,
			created_at timestamptz NOT NULL,
			payload text NOT NULL
		)`); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DROP TABLE IF EXISTS ci_retention_source`)
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM radar_retention_archive WHERE source_table=$1`, sourceTable)
		_, _ = db.ExecContext(cleanupCtx, `
			DELETE FROM radar_retention_runs r
			WHERE NOT EXISTS (SELECT 1 FROM radar_retention_archive a WHERE a.run_id=r.id)
			  AND r.detail->>'ci_test'='retention_archive_delete'`)
	}()

	target := retentionTarget{
		Table: sourceTable, IDColumn: "id",
		Where: "t.created_at < $1", Order: "t.created_at ASC",
	}
	query := retentionArchiveQuery(target)
	cutoff := time.Now().UTC().Add(-24 * time.Hour)

	insertRun := func() string {
		t.Helper()
		var runID string
		if err := db.QueryRowContext(ctx, `
			INSERT INTO radar_retention_runs (id,cutoff,status,detail)
			VALUES (gen_random_uuid(),$1,'running','{"ci_test":"retention_archive_delete"}'::jsonb)
			RETURNING id::text`, cutoff).Scan(&runID); err != nil {
			t.Fatal(err)
		}
		return runID
	}
	insertRows := func(first, second string) {
		t.Helper()
		// Use a fixed timestamp so the resumed pass really reconstructs the
		// identical JSON payload. A fresh now()-interval value differs at
		// microsecond precision and correctly fails exact-payload verification.
		if _, err := db.ExecContext(ctx, `
			INSERT INTO ci_retention_source (id,created_at,payload) VALUES
			('11111111-1111-4111-8111-111111111111',TIMESTAMPTZ '2026-01-01 00:00:00+00',$1),
			('22222222-2222-4222-8222-222222222222',TIMESTAMPTZ '2026-01-01 00:00:00+00',$2)`, first, second); err != nil {
			t.Fatal(err)
		}
	}
	runBatch := func(runID string) (selected, archived, verified, deleted int64) {
		t.Helper()
		if err := db.QueryRowContext(ctx, query, cutoff, 100, runID, sourceTable).
			Scan(&selected, &archived, &verified, &deleted); err != nil {
			t.Fatal(err)
		}
		return
	}
	assertSourceCount := func(want int) {
		t.Helper()
		var got int
		if err := db.QueryRowContext(ctx, `SELECT count(*) FROM ci_retention_source`).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != want {
			t.Fatalf("source row count=%d want=%d", got, want)
		}
	}

	insertRows("alpha", "beta")
	selected, archived, verified, deleted := runBatch(insertRun())
	if selected != 2 || archived != 2 || verified != 2 || deleted != 2 {
		t.Fatalf("initial batch selected=%d archived=%d verified=%d deleted=%d", selected, archived, verified, deleted)
	}
	assertSourceCount(0)

	// A resumed pass over already archived rows must still return the conflict
	// rows, verify the unchanged payload/checksum and delete the source rows.
	insertRows("alpha", "beta")
	selected, archived, verified, deleted = runBatch(insertRun())
	if selected != 2 || archived != 2 || verified != 2 || deleted != 2 {
		t.Fatalf("resumed batch selected=%d archived=%d verified=%d deleted=%d", selected, archived, verified, deleted)
	}
	assertSourceCount(0)

	// A source row reappearing with changed payload must fail closed. The
	// conflict row is returned, but it cannot enter verified or removed.
	insertRows("changed-alpha", "changed-beta")
	selected, archived, verified, deleted = runBatch(insertRun())
	if selected != 2 || archived != 2 || verified != 0 || deleted != 0 {
		t.Fatalf("mismatch batch selected=%d archived=%d verified=%d deleted=%d", selected, archived, verified, deleted)
	}
	assertSourceCount(2)
}
