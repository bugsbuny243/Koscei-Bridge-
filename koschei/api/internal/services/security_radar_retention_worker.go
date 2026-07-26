package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

// Radar retention worker.
//
// Release gate #699 changes the deletion contract: expired rows are archived
// with a deterministic checksum before deletion. The delete is gated by the
// same statement's verified archive set, so an unarchived or mismatched row is
// not deletable. The archive remains a staging ledger until an external export
// stamps exported_at.
//
// Config:
//
//	KOSCHEI_RADAR_RETENTION_DISABLED=1          worker off
//	KOSCHEI_RADAR_RETENTION_DAYS=30             window (min 7, max 365)
//	KOSCHEI_RADAR_RETENTION_INTERVAL_HOURS=12   frequency (min 1, max 48)
//	KOSCHEI_RADAR_ARCHIVE_BACKLOG_MAX=2000000   unexported rows allowed
//	KOSCHEI_RADAR_ARCHIVE_PRUNE_DAYS=7          exported rows kept before prune
const radarRetentionBatchSize = 5000
const radarRetentionMaxBatchesPerTable = 40

type retentionTarget struct {
	Table    string
	IDColumn string
	Where    string // $1 is the cutoff timestamp
	Order    string
}

// Targets are ordered by dependency. Stream-processing rows are archived before
// stream events, and stream events are never deleted while any processing row
// remains. This prevents the ON DELETE CASCADE relation from bypassing archive.
var radarRetentionTargets = []retentionTarget{
	{
		Table: "security_radar_verdicts", IDColumn: "id",
		Where: "t.created_at < $1", Order: "t.created_at ASC",
	},
	{
		Table: "security_radar_events", IDColumn: "id",
		Where: `t.created_at < $1
		  AND NOT EXISTS (SELECT 1 FROM security_radar_verdicts v WHERE v.event_id = t.id)`,
		Order: "t.created_at ASC",
	},
	{
		Table: "security_radar_seen_signatures", IDColumn: "id",
		Where: "t.created_at < $1", Order: "t.created_at ASC",
	},
	{
		Table: "arvis_stream_processing", IDColumn: "stream_event_id",
		Where: `t.created_at < $1
		  AND t.status NOT IN ('pending','processing')`,
		Order: "t.created_at ASC",
	},
	{
		Table: "security_radar_stream_events", IDColumn: "id",
		Where: `t.created_at < $1
		  AND NOT EXISTS (
			SELECT 1 FROM arvis_stream_processing p WHERE p.stream_event_id = t.id
		  )`,
		Order: "t.created_at ASC",
	},
	{
		Table: "token_trade_events", IDColumn: "id",
		Where: `COALESCE(t.block_time,t.created_at) < now()-interval '72 hours'
		  AND NOT EXISTS (
			SELECT 1 FROM watchlist_targets w
			WHERE w.status='active' AND w.target=t.mint
		  )
		  AND NOT EXISTS (
			SELECT 1 FROM security_radar_verdicts v
			WHERE v.target=t.mint AND v.created_at >= $1
		  )`,
		Order: "COALESCE(t.block_time,t.created_at) ASC",
	},
}

func StartSecurityRadarRetentionWorker(ctx context.Context, db *sql.DB) func() {
	if db == nil || envBool("KOSCHEI_RADAR_RETENTION_DISABLED") {
		return func() {}
	}
	workerCtx, cancel := context.WithCancel(ctx)
	go (&securityRadarRetentionWorker{
		db:       db,
		days:     radarRetentionDays(),
		interval: radarRetentionInterval(),
	}).start(workerCtx)
	return cancel
}

type securityRadarRetentionWorker struct {
	db       *sql.DB
	days     int
	interval time.Duration
}

type runStats struct {
	Selected   int64
	Archived   int64
	Verified   int64
	Deleted    int64
	Mismatches int64
	Pruned     int64
	PerTable   map[string]int64
	HaltReason string
}

func (w *securityRadarRetentionWorker) start(ctx context.Context) {
	if w == nil || w.db == nil {
		return
	}
	log.Printf("radar retention worker started window=%dd interval=%s mode=archive-verify-delete", w.days, w.interval)
	w.runOnce(ctx)
	ticker := time.NewTicker(w.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("radar retention worker stopped")
			return
		case <-ticker.C:
			w.runOnce(ctx)
		}
	}
}

func (w *securityRadarRetentionWorker) runOnce(ctx context.Context) {
	cutoff := time.Now().UTC().AddDate(0, 0, -w.days)
	if !w.archiveReady(ctx) {
		log.Printf("radar retention: archive tables unavailable; nothing deleted (apply migration 084)")
		return
	}
	backlog, err := w.unexportedBacklog(ctx)
	if err != nil {
		log.Printf("radar retention: backlog probe failed: %v", err)
		return
	}
	if limit := radarArchiveBacklogMax(); backlog > limit {
		reason := fmt.Sprintf("unexported archive backlog %d exceeds ceiling %d", backlog, limit)
		log.Printf("radar retention: halted; %s", reason)
		w.recordHaltedRun(ctx, cutoff, reason)
		return
	}

	runID, err := w.beginRun(ctx, cutoff)
	if err != nil {
		log.Printf("radar retention: could not open run ledger: %v", err)
		return
	}
	stats := runStats{PerTable: map[string]int64{}}
	for _, target := range radarRetentionTargets {
		if ctx.Err() != nil {
			stats.HaltReason = "retention context canceled"
			break
		}
		stats.PerTable[target.Table] = w.archiveAndDelete(ctx, runID, target, cutoff, &stats)
		if stats.HaltReason != "" {
			break
		}
	}

	if stats.HaltReason == "" {
		mismatches, verifyErr := w.verifyRunChecksums(ctx, runID)
		switch {
		case verifyErr != nil:
			stats.HaltReason = "checksum verification failed: " + verifyErr.Error()
		case mismatches > 0:
			stats.Mismatches = mismatches
			stats.HaltReason = fmt.Sprintf("%d archived rows failed checksum verification", mismatches)
		}
	}
	if stats.HaltReason == "" {
		stats.Pruned = w.pruneExportedArchive(ctx)
	}
	w.finishRun(ctx, runID, stats)

	if stats.HaltReason != "" {
		log.Printf("radar retention run %s HALTED: %s (archived=%d verified=%d deleted=%d)",
			runID, stats.HaltReason, stats.Archived, stats.Verified, stats.Deleted)
		return
	}
	if stats.Deleted > 0 || stats.Pruned > 0 {
		log.Printf("radar retention run %s: archived=%d verified=%d deleted=%d pruned=%d cutoff=%s detail=%v",
			runID, stats.Archived, stats.Verified, stats.Deleted, stats.Pruned,
			cutoff.Format(time.RFC3339), stats.PerTable)
	}
}

func (w *securityRadarRetentionWorker) archiveAndDelete(ctx context.Context, runID string, target retentionTarget, cutoff time.Time, stats *runStats) int64 {
	query := retentionArchiveQuery(target)
	var total int64
	for batch := 0; batch < radarRetentionMaxBatchesPerTable; batch++ {
		if ctx.Err() != nil {
			stats.HaltReason = "retention context canceled"
			return total
		}
		stepCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
		var selected, archived, verified, removed int64
		err := w.db.QueryRowContext(stepCtx, query, cutoff, radarRetentionBatchSize, runID, target.Table).
			Scan(&selected, &archived, &verified, &removed)
		cancel()
		if err != nil {
			stats.HaltReason = fmt.Sprintf("%s archive/delete failed: %v", target.Table, err)
			log.Printf("radar retention: %s", stats.HaltReason)
			return total
		}
		stats.Selected += selected
		stats.Archived += archived
		stats.Verified += verified
		stats.Deleted += removed
		total += removed

		if archived != selected || verified != archived || removed != verified {
			stats.HaltReason = fmt.Sprintf(
				"%s batch mismatch selected=%d archived=%d verified=%d deleted=%d",
				target.Table, selected, archived, verified, removed,
			)
			return total
		}
		if selected < radarRetentionBatchSize {
			return total
		}
	}
	log.Printf("radar retention: %s hit per-run batch cap; remaining rows handled next run", target.Table)
	return total
}

// retentionArchiveQuery constructs SQL only from package-owned identifiers.
// The entire batch is all-or-nothing for deletion: removed reads from batch_ok,
// which exists only when every selected row has an exact payload/checksum match
// in the archive.
func retentionArchiveQuery(target retentionTarget) string {
	idColumn := strings.TrimSpace(target.IDColumn)
	if idColumn == "" {
		idColumn = "id"
	}
	// #nosec G201 -- target fields are package constants in
	// radarRetentionTargets; no request or operator input reaches identifiers.
	return `
		WITH expiring AS (
			SELECT t.` + idColumn + ` AS row_id, to_jsonb(t) AS payload
			FROM ` + target.Table + ` t
			WHERE ` + target.Where + `
			ORDER BY ` + target.Order + `
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		),
		archived AS (
			INSERT INTO radar_retention_archive
			(run_id, source_table, source_id, row_checksum, payload)
			SELECT $3::uuid, $4, e.row_id::text,
			       encode(sha256(convert_to(e.payload::text, 'UTF8')), 'hex'),
			       e.payload
			FROM expiring e
			ON CONFLICT (source_table, source_id)
			DO UPDATE SET run_id=EXCLUDED.run_id, archived_at=now()
			RETURNING source_id, row_checksum, payload
		),
		verified AS (
			SELECT a.source_id
			FROM archived a
			JOIN expiring e ON e.row_id::text=a.source_id
			WHERE a.payload=e.payload
			  AND a.row_checksum=encode(sha256(convert_to(e.payload::text, 'UTF8')), 'hex')
		),
		batch_counts AS (
			SELECT (SELECT count(*) FROM expiring) AS selected_count,
			       (SELECT count(*) FROM archived) AS archived_count,
			       (SELECT count(*) FROM verified) AS verified_count
		),
		batch_ok AS (
			SELECT 1 FROM batch_counts
			WHERE selected_count=archived_count AND archived_count=verified_count
		),
		removed AS (
			DELETE FROM ` + target.Table + ` t
			WHERE t.` + idColumn + `::text IN (SELECT source_id FROM verified)
			  AND EXISTS (SELECT 1 FROM batch_ok)
			RETURNING t.` + idColumn + `
		)
		SELECT selected_count, archived_count, verified_count,
		       (SELECT count(*) FROM removed)
		FROM batch_counts`
}

func (w *securityRadarRetentionWorker) verifyRunChecksums(ctx context.Context, runID string) (int64, error) {
	verifyCtx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	var mismatches int64
	err := w.db.QueryRowContext(verifyCtx, `
		SELECT count(*)
		FROM radar_retention_archive
		WHERE run_id=$1::uuid
		  AND row_checksum<>encode(sha256(convert_to(payload::text,'UTF8')),'hex')`, runID).
		Scan(&mismatches)
	return mismatches, err
}

func (w *securityRadarRetentionWorker) pruneExportedArchive(ctx context.Context) int64 {
	pruneCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	result, err := w.db.ExecContext(pruneCtx, `
		DELETE FROM radar_retention_archive
		WHERE id IN (
			SELECT id FROM radar_retention_archive
			WHERE exported_at IS NOT NULL
			  AND exported_at < now()-make_interval(days=>$1)
			ORDER BY exported_at ASC
			LIMIT $2
		)`, radarArchivePruneDays(), radarRetentionBatchSize)
	if err != nil {
		log.Printf("radar retention: archive prune error: %v", err)
		return 0
	}
	pruned, _ := result.RowsAffected()
	return pruned
}

func (w *securityRadarRetentionWorker) archiveReady(ctx context.Context) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var ready bool
	err := w.db.QueryRowContext(probeCtx, `
		SELECT to_regclass('radar_retention_archive') IS NOT NULL
		   AND to_regclass('radar_retention_runs') IS NOT NULL`).Scan(&ready)
	return err == nil && ready
}

func (w *securityRadarRetentionWorker) unexportedBacklog(ctx context.Context) (int64, error) {
	probeCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var backlog int64
	err := w.db.QueryRowContext(probeCtx, `
		SELECT count(*) FROM radar_retention_archive WHERE exported_at IS NULL`).Scan(&backlog)
	return backlog, err
}

func (w *securityRadarRetentionWorker) beginRun(ctx context.Context, cutoff time.Time) (string, error) {
	runCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	var runID string
	err := w.db.QueryRowContext(runCtx, `
		INSERT INTO radar_retention_runs (id,cutoff,status)
		VALUES (gen_random_uuid(),$1,'running')
		RETURNING id::text`, cutoff).Scan(&runID)
	return runID, err
}

func (w *securityRadarRetentionWorker) finishRun(ctx context.Context, runID string, stats runStats) {
	status := "completed"
	if stats.HaltReason != "" {
		status = "halted"
	}
	finishCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	if _, err := w.db.ExecContext(finishCtx, `
		UPDATE radar_retention_runs
		SET finished_at=now(),status=$2,selected_rows=$3,archived_rows=$4,
		    verified_rows=$5,deleted_rows=$6,checksum_mismatches=$7,
		    pruned_rows=$8,detail=$9::jsonb
		WHERE id=$1::uuid`, runID, status, stats.Selected, stats.Archived,
		stats.Verified, stats.Deleted, stats.Mismatches, stats.Pruned,
		retentionDetailJSON(stats)); err != nil {
		log.Printf("radar retention: run ledger update failed for %s: %v", runID, err)
	}
}

func (w *securityRadarRetentionWorker) recordHaltedRun(ctx context.Context, cutoff time.Time, reason string) {
	runID, err := w.beginRun(ctx, cutoff)
	if err != nil {
		return
	}
	w.finishRun(ctx, runID, runStats{PerTable: map[string]int64{}, HaltReason: reason})
}

func retentionDetailJSON(stats runStats) string {
	detail := map[string]any{"per_table": stats.PerTable}
	if stats.HaltReason != "" {
		detail["halt_reason"] = stats.HaltReason
	}
	encoded, err := json.Marshal(detail)
	if err != nil {
		return "{}"
	}
	return string(encoded)
}

func radarRetentionDays() int {
	if raw := strings.TrimSpace(os.Getenv("KOSCHEI_RADAR_RETENTION_DAYS")); raw != "" {
		if days, err := strconv.Atoi(raw); err == nil && days >= 7 && days <= 365 {
			return days
		}
	}
	return 30
}

func radarRetentionInterval() time.Duration {
	if raw := strings.TrimSpace(os.Getenv("KOSCHEI_RADAR_RETENTION_INTERVAL_HOURS")); raw != "" {
		if hours, err := strconv.Atoi(raw); err == nil && hours >= 1 && hours <= 48 {
			return time.Duration(hours) * time.Hour
		}
	}
	return 12 * time.Hour
}

func radarArchiveBacklogMax() int64 {
	if raw := strings.TrimSpace(os.Getenv("KOSCHEI_RADAR_ARCHIVE_BACKLOG_MAX")); raw != "" {
		if value, err := strconv.ParseInt(raw, 10, 64); err == nil && value >= 10000 {
			return value
		}
	}
	return 2000000
}

func radarArchivePruneDays() int {
	if raw := strings.TrimSpace(os.Getenv("KOSCHEI_RADAR_ARCHIVE_PRUNE_DAYS")); raw != "" {
		if days, err := strconv.Atoi(raw); err == nil && days >= 1 && days <= 365 {
			return days
		}
	}
	return 7
}
