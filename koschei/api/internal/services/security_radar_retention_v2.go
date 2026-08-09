package services

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"log"
	"strings"
	"time"
)

const (
	retentionV2DefaultBatch = 5000
	retentionV2MinBatch     = 50
	retentionV2MaxBatches   = 40
)

// StartSecurityRadarRetentionWorkerV2 preserves the archive-before-delete
// contract while tuning work to measured production latency. The legacy worker
// remains available for rollback, but production startup uses this bounded v2
// path once wired by the watcher.
func StartSecurityRadarRetentionWorkerV2(ctx context.Context, db *sql.DB) func() {
	if db == nil || envBool("KOSCHEI_RADAR_RETENTION_DISABLED") {
		return func() {}
	}
	workerCtx, cancel := context.WithCancel(ctx)
	worker := &securityRadarRetentionWorkerV2{base: &securityRadarRetentionWorker{
		db: db, days: radarRetentionDays(), interval: radarRetentionInterval(),
	}}
	go worker.start(workerCtx)
	return cancel
}

type securityRadarRetentionWorkerV2 struct {
	base *securityRadarRetentionWorker
}

func (w *securityRadarRetentionWorkerV2) start(ctx context.Context) {
	if w == nil || w.base == nil || w.base.db == nil {
		return
	}
	w.recoverStaleRuns(ctx)
	log.Printf("radar retention v2 started window=%dd interval=%s mode=archive-verify-delete measured-batches", w.base.days, w.base.interval)
	w.runOnce(ctx)
	ticker := time.NewTicker(w.base.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("radar retention v2 stopped")
			return
		case <-ticker.C:
			w.recoverStaleRuns(ctx)
			w.runOnce(ctx)
		}
	}
}

func (w *securityRadarRetentionWorkerV2) recoverStaleRuns(ctx context.Context) {
	if w == nil || w.base == nil || w.base.db == nil {
		return
	}
	recoverCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	defer cancel()
	result, err := w.base.db.ExecContext(recoverCtx, `
		UPDATE radar_retention_runs
		SET status='halted',
		    finished_at=COALESCE(finished_at,now()),
		    detail=COALESCE(detail,'{}'::jsonb) || jsonb_build_object(
		      'halt_reason','recovered stale retention run after process interruption',
		      'recovered_at',now()
		    )
		WHERE status='running'
		  AND finished_at IS NULL
		  AND started_at < now()-interval '15 minutes'`)
	if err != nil {
		if !isUndefinedTableError(err) && ctx.Err() == nil {
			log.Printf("radar retention v2 stale-run recovery failed: %v", err)
		}
		return
	}
	if rows, err := result.RowsAffected(); err == nil && rows > 0 {
		log.Printf("radar retention v2 recovered %d stale run-ledger row(s)", rows)
	}
}

func (w *securityRadarRetentionWorkerV2) runOnce(ctx context.Context) {
	if w == nil || w.base == nil || w.base.db == nil {
		return
	}
	cutoff := time.Now().UTC().AddDate(0, 0, -w.base.days)
	if !w.base.archiveReady(ctx) {
		log.Printf("radar retention v2: archive tables unavailable; nothing deleted")
		return
	}
	if err := w.base.exportPendingArchive(ctx, "before_retention_v2"); err != nil {
		log.Printf("radar retention v2: halted; %v", err)
		return
	}
	backlog, err := w.base.unexportedBacklog(ctx)
	if err != nil {
		log.Printf("radar retention v2: backlog probe failed: %v", err)
		return
	}
	if limit := radarArchiveBacklogMax(); backlog > limit {
		reason := fmt.Sprintf("unexported archive backlog %d exceeds ceiling %d", backlog, limit)
		log.Printf("radar retention v2: halted; %s", reason)
		w.base.recordHaltedRun(ctx, cutoff, reason)
		return
	}

	runID, err := w.base.beginRun(ctx, cutoff)
	if err != nil {
		log.Printf("radar retention v2: could not open run ledger: %v", err)
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
		mismatches, verifyErr := w.base.verifyRunChecksums(ctx, runID)
		switch {
		case verifyErr != nil:
			stats.HaltReason = "checksum verification failed: " + verifyErr.Error()
		case mismatches > 0:
			stats.Mismatches = mismatches
			stats.HaltReason = fmt.Sprintf("%d archived rows failed checksum verification", mismatches)
		}
	}
	if stats.HaltReason == "" {
		if err := w.base.exportPendingArchive(ctx, "after_retention_v2"); err != nil {
			stats.HaltReason = err.Error()
		}
	}
	if stats.HaltReason == "" {
		stats.Pruned = w.base.pruneExportedArchive(ctx)
	}
	w.base.finishRun(ctx, runID, stats)

	if stats.HaltReason != "" {
		log.Printf("radar retention v2 run %s HALTED: %s (archived=%d verified=%d deleted=%d)",
			runID, stats.HaltReason, stats.Archived, stats.Verified, stats.Deleted)
		return
	}
	if stats.Deleted > 0 || stats.Pruned > 0 {
		log.Printf("radar retention v2 run %s: archived=%d verified=%d deleted=%d pruned=%d cutoff=%s detail=%v",
			runID, stats.Archived, stats.Verified, stats.Deleted, stats.Pruned,
			cutoff.Format(time.RFC3339), stats.PerTable)
	}
}

func retentionV2InitialBatch(target retentionTarget) int {
	switch strings.TrimSpace(target.Table) {
	case "security_radar_verdicts":
		// Production EXPLAIN ANALYZE measured ~11s merely to read, JSON-encode and
		// hash 250 expired verdict rows. Start at that measured safe lock scope.
		return 250
	case "security_radar_events":
		return 1000
	default:
		return retentionV2DefaultBatch
	}
}

func retentionV2StepTimeout(target retentionTarget) time.Duration {
	switch strings.TrimSpace(target.Table) {
	case "security_radar_verdicts":
		// 60s is bounded but leaves room for archive insert, verification and
		// delete after the measured ~11s source/hash phase.
		return 60 * time.Second
	case "security_radar_events":
		return 45 * time.Second
	default:
		return 30 * time.Second
	}
}

func retentionV2NextBatch(current int) int {
	if current <= retentionV2MinBatch {
		return retentionV2MinBatch
	}
	next := current / 2
	if next < retentionV2MinBatch {
		next = retentionV2MinBatch
	}
	return next
}

func retentionV2DeadlineError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "57014") ||
		strings.Contains(message, "canceling statement due to user request") ||
		strings.Contains(message, "statement timeout") ||
		strings.Contains(message, "deadline exceeded")
}

func (w *securityRadarRetentionWorkerV2) archiveAndDelete(ctx context.Context, runID string, target retentionTarget, cutoff time.Time, stats *runStats) int64 {
	query := retentionArchiveQueryV2(target)
	var total int64
	batchLimit := retentionV2InitialBatch(target)
	for batch := 0; batch < retentionV2MaxBatches; batch++ {
		if ctx.Err() != nil {
			stats.HaltReason = "retention context canceled"
			return total
		}
		for {
			stepCtx, cancel := context.WithTimeout(ctx, retentionV2StepTimeout(target))
			var selected, archived, verified, removed int64
			err := w.base.db.QueryRowContext(stepCtx, query, cutoff, batchLimit, runID, target.Table).
				Scan(&selected, &archived, &verified, &removed)
			cancel()
			if err != nil {
				if retentionV2DeadlineError(err) && batchLimit > retentionV2MinBatch {
					next := retentionV2NextBatch(batchLimit)
					log.Printf("radar retention v2: %s deadline at limit=%d; retrying limit=%d", target.Table, batchLimit, next)
					batchLimit = next
					continue
				}
				stats.HaltReason = fmt.Sprintf("%s archive/delete failed at batch_limit=%d: %v", target.Table, batchLimit, err)
				return total
			}

			stats.Selected += selected
			stats.Archived += archived
			stats.Verified += verified
			stats.Deleted += removed
			total += removed
			if archived != selected || verified != archived || removed != verified {
				stats.HaltReason = fmt.Sprintf("%s batch mismatch selected=%d archived=%d verified=%d deleted=%d",
					target.Table, selected, archived, verified, removed)
				return total
			}
			if selected < int64(batchLimit) {
				return total
			}
			break
		}
	}
	log.Printf("radar retention v2: %s hit per-run batch cap at limit=%d; remaining rows deferred", target.Table, batchLimit)
	return total
}

// retentionArchiveQueryV2 computes the canonical payload checksum exactly once
// in a materialized CTE. Archive, exact verification and source deletion still
// happen in one statement; a timeout rolls the whole batch back.
func retentionArchiveQueryV2(target retentionTarget) string {
	idColumn := strings.TrimSpace(target.IDColumn)
	if idColumn == "" {
		idColumn = "id"
	}
	// #nosec G201 -- identifiers and predicates come exclusively from the
	// package-owned radarRetentionTargets registry.
	return `
		WITH candidate_rows AS MATERIALIZED (
			SELECT t.` + idColumn + ` AS row_id, to_jsonb(t) AS payload
			FROM ` + target.Table + ` t
			WHERE ` + target.Where + `
			ORDER BY ` + target.Order + `
			LIMIT $2
			FOR UPDATE SKIP LOCKED
		),
		expiring AS MATERIALIZED (
			SELECT row_id,payload,
			       encode(sha256(convert_to(payload::text,'UTF8')),'hex') AS row_checksum
			FROM candidate_rows
		),
		archived AS (
			INSERT INTO radar_retention_archive
			(run_id,source_table,source_id,row_checksum,payload)
			SELECT $3::uuid,$4,e.row_id::text,e.row_checksum,e.payload
			FROM expiring e
			ON CONFLICT (source_table,source_id)
			DO UPDATE SET run_id=EXCLUDED.run_id,archived_at=now()
			RETURNING source_id,row_checksum,payload
		),
		verified AS (
			SELECT a.source_id
			FROM archived a
			JOIN expiring e ON e.row_id::text=a.source_id
			WHERE a.payload=e.payload AND a.row_checksum=e.row_checksum
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
		SELECT selected_count,archived_count,verified_count,
		       (SELECT count(*) FROM removed)
		FROM batch_counts`
}
