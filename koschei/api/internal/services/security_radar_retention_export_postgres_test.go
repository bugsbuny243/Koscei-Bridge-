package services

import (
	"context"
	"database/sql"
	"os"
	"strings"
	"testing"
	"time"

	"koschei/api/internal/services/retentionexport"

	_ "github.com/lib/pq"
)

func TestRetentionArchiveExportPostgres17(t *testing.T) {
	databaseURL := os.Getenv("KOSCHEI_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KOSCHEI_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(4)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	const sourceTable = "ci_retention_export_source"
	var retentionRunID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO radar_retention_runs (id,cutoff,status,detail)
		VALUES (gen_random_uuid(),now()-interval '30 days','completed','{"ci_test":"retention_archive_export"}'::jsonb)
		RETURNING id::text`).Scan(&retentionRunID); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cleanupCtx, cleanupCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cleanupCancel()
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM radar_retention_archive WHERE source_table=$1`, sourceTable)
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM radar_retention_export_runs WHERE detail->>'ci_test'='retention_archive_export' OR sink='filesystem'`)
		_, _ = db.ExecContext(cleanupCtx, `DELETE FROM radar_retention_runs WHERE id=$1::uuid`, retentionRunID)
	}()

	if _, err := db.ExecContext(ctx, `
		INSERT INTO radar_retention_archive
		(run_id,source_table,source_id,row_checksum,payload,archived_at)
		SELECT $1::uuid,$2,v.source_id,
		       encode(sha256(convert_to(v.payload::text,'UTF8')),'hex'),
		       v.payload,now()-interval '10 days'
		FROM (VALUES
			('row-1','{"id":1,"kind":"event"}'::jsonb),
			('row-2','{"id":2,"kind":"verdict"}'::jsonb)
		) AS v(source_id,payload)`, retentionRunID, sourceTable); err != nil {
		t.Fatal(err)
	}

	sink, err := retentionexport.NewFilesystemSink(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	result, err := (retentionexport.Exporter{
		Repository: retentionexport.NewSQLRepository(db),
		Sink:       sink,
		Config: retentionexport.Config{
			Sink: "filesystem", BatchSize: 100, MaxBatches: 2, Prefix: "ci-retention",
		},
	}).Run(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExportedRows != 2 || result.ObjectCount != 1 || !strings.Contains(result.LastExportRef, "#sha256=") {
		t.Fatalf("unexpected export result: %+v", result)
	}
	if _, err := db.ExecContext(ctx, `
		UPDATE radar_retention_export_runs
		SET detail=jsonb_set(detail,'{ci_test}','"retention_archive_export"'::jsonb,true)
		WHERE id=$1::uuid`, result.RunID); err != nil {
		t.Fatal(err)
	}
	var exported int
	if err := db.QueryRowContext(ctx, `
		SELECT count(*) FROM radar_retention_archive
		WHERE source_table=$1 AND exported_at IS NOT NULL AND export_ref LIKE '%#sha256=%'`, sourceTable).Scan(&exported); err != nil {
		t.Fatal(err)
	}
	if exported != 2 {
		t.Fatalf("exported rows=%d want=2", exported)
	}

	if _, err := db.ExecContext(ctx, `
		UPDATE radar_retention_archive SET exported_at=now()-interval '8 days'
		WHERE source_table=$1`, sourceTable); err != nil {
		t.Fatal(err)
	}
	worker := &securityRadarRetentionWorker{db: db, days: 30, interval: 12 * time.Hour}
	if pruned := worker.pruneExportedArchive(ctx); pruned != 2 {
		t.Fatalf("pruned rows=%d want=2", pruned)
	}
	var remaining int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM radar_retention_archive WHERE source_table=$1`, sourceTable).Scan(&remaining); err != nil {
		t.Fatal(err)
	}
	if remaining != 0 {
		t.Fatalf("archive rows remain after verified export prune: %d", remaining)
	}
}
