package retentionexport

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/lib/pq"
)

const exportAdvisoryLockID int64 = 0x4b4f534348454958 // "KOSCHEIX"

type SQLRepository struct {
	db *sql.DB
}

func NewSQLRepository(db *sql.DB) *SQLRepository {
	return &SQLRepository{db: db}
}

func (r *SQLRepository) TryLock(ctx context.Context) (func(), bool, error) {
	if r == nil || r.db == nil {
		return func() {}, false, fmt.Errorf("retention export database is required")
	}
	lockCtx, cancel := operationContext(ctx)
	defer cancel()
	conn, err := r.db.Conn(lockCtx)
	if err != nil {
		return func() {}, false, err
	}
	var acquired bool
	if err := conn.QueryRowContext(lockCtx, `SELECT pg_try_advisory_lock($1)`, exportAdvisoryLockID).Scan(&acquired); err != nil {
		_ = conn.Close()
		return func() {}, false, err
	}
	if !acquired {
		_ = conn.Close()
		return func() {}, false, nil
	}
	release := func() {
		releaseCtx, releaseCancel := context.WithTimeout(context.Background(), 5_000_000_000)
		defer releaseCancel()
		_, _ = conn.ExecContext(releaseCtx, `SELECT pg_advisory_unlock($1)`, exportAdvisoryLockID)
		_ = conn.Close()
	}
	return release, true, nil
}

func (r *SQLRepository) StartRun(ctx context.Context, sink string) (string, error) {
	runCtx, cancel := operationContext(ctx)
	defer cancel()
	var runID string
	err := r.db.QueryRowContext(runCtx, `
		INSERT INTO radar_retention_export_runs (id,status,sink)
		VALUES (gen_random_uuid(),'running',$1)
		RETURNING id::text`, strings.TrimSpace(sink)).Scan(&runID)
	return runID, err
}

func (r *SQLRepository) LoadPending(ctx context.Context, limit int) ([]ArchiveRow, error) {
	queryCtx, cancel := operationContext(ctx)
	defer cancel()
	rows, err := r.db.QueryContext(queryCtx, `
		SELECT id,run_id::text,source_table,source_id,row_checksum,payload::text,archived_at
		FROM radar_retention_archive
		WHERE exported_at IS NULL
		ORDER BY archived_at ASC,id ASC
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := []ArchiveRow{}
	for rows.Next() {
		var row ArchiveRow
		var payload []byte
		if err := rows.Scan(&row.ID, &row.RunID, &row.SourceTable, &row.SourceID, &row.RowChecksum, &payload, &row.ArchivedAt); err != nil {
			return nil, err
		}
		row.Payload = append(json.RawMessage(nil), payload...)
		result = append(result, row)
	}
	return result, rows.Err()
}

func (r *SQLRepository) MarkExported(ctx context.Context, runID string, rows []ArchiveRow, exportRef, batchChecksum string) error {
	if len(rows) == 0 {
		return nil
	}
	ids := make([]int64, 0, len(rows))
	checksums := make([]string, 0, len(rows))
	for _, row := range rows {
		ids = append(ids, row.ID)
		checksums = append(checksums, strings.TrimSpace(row.RowChecksum))
	}
	txCtx, cancel := operationContext(ctx)
	defer cancel()
	tx, err := r.db.BeginTx(txCtx, &sql.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	var updated int
	err = tx.QueryRowContext(txCtx, `
		WITH expected AS (
			SELECT * FROM unnest($1::bigint[],$2::text[]) AS e(id,row_checksum)
		), updated AS (
			UPDATE radar_retention_archive a
			SET exported_at=now(),export_ref=$3
			FROM expected e
			WHERE a.id=e.id
			  AND a.row_checksum=e.row_checksum
			  AND a.exported_at IS NULL
			RETURNING a.id
		)
		SELECT count(*) FROM updated`, pq.Array(ids), pq.Array(checksums), strings.TrimSpace(exportRef)).Scan(&updated)
	if err != nil {
		return err
	}
	if updated != len(rows) {
		return fmt.Errorf("atomic export mark expected %d rows, updated %d", len(rows), updated)
	}
	if _, err := tx.ExecContext(txCtx, `
		UPDATE radar_retention_export_runs
		SET last_export_ref=$2,detail=jsonb_set(detail,'{last_batch_checksum}',to_jsonb($3::text),true)
		WHERE id=$1::uuid`, runID, strings.TrimSpace(exportRef), strings.TrimSpace(batchChecksum)); err != nil {
		return err
	}
	return tx.Commit()
}

func (r *SQLRepository) FinishRun(ctx context.Context, runID string, result Result, runErr error) error {
	status := "completed"
	errorMessage := ""
	if runErr != nil {
		status = "failed"
		errorMessage = runErr.Error()
	}
	detail, _ := json.Marshal(map[string]any{
		"lock_acquired": result.LockAcquired,
	})
	_, err := r.db.ExecContext(ctx, `
		UPDATE radar_retention_export_runs
		SET finished_at=now(),status=$2,selected_rows=$3,exported_rows=$4,
		    object_count=$5,bytes_exported=$6,checksum_mismatches=$7,
		    last_export_ref=NULLIF($8,''),error_message=NULLIF($9,''),detail=$10::jsonb
		WHERE id=$1::uuid`, runID, status, result.SelectedRows, result.ExportedRows,
		result.ObjectCount, result.BytesExported, result.ChecksumMismatches,
		result.LastExportRef, errorMessage, string(detail))
	return err
}
