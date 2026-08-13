package services

import (
	"context"
	"database/sql"
	"log"
	"strings"
	"time"

	"koschei/api/internal/jobs"
)

const canonicalInvestigationJobType = "canonical_investigation"

// StartArvisStreamCanonicalBridge turns trusted Radar stream observations into
// canonical investigation jobs. It intentionally does not calculate, grade or
// sign a final verdict: that authority belongs to the unified canonical worker.
func StartArvisStreamCanonicalBridge(ctx context.Context, db *sql.DB) func() {
	if db == nil || envBool("ARVIS_STREAM_VERDICT_DISABLED") {
		return func() {}
	}
	bridgeCtx, cancel := context.WithCancel(ctx)
	bridge := &arvisStreamCanonicalBridge{db: db, jobs: jobs.NewStore(db), interval: arvisStreamVerdictInterval(), batchSize: arvisStreamVerdictBatchSize()}
	go bridge.start(bridgeCtx)
	return cancel
}

type arvisStreamCanonicalBridge struct {
	db        *sql.DB
	jobs      *jobs.Store
	interval  time.Duration
	batchSize int
}

func (b *arvisStreamCanonicalBridge) start(ctx context.Context) {
	if b == nil || b.db == nil || b.jobs == nil {
		return
	}
	log.Printf("arvis stream canonical bridge started interval=%s batch=%d", b.interval, b.batchSize)
	b.run(ctx)
	ticker := time.NewTicker(b.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			log.Printf("arvis stream canonical bridge stopped")
			return
		case <-ticker.C:
			b.run(ctx)
		}
	}
}

func (b *arvisStreamCanonicalBridge) run(ctx context.Context) {
	rows, err := b.db.QueryContext(ctx, `
		SELECT s.id::text,
		       COALESCE(s.target,''),
		       COALESCE(s.network,'solana-mainnet'),
		       COALESCE(s.module_id,''),
		       COALESCE(s.signature,'')
		FROM security_radar_stream_events s
		LEFT JOIN arvis_stream_processing p ON p.stream_event_id=s.id
		WHERE COALESCE(s.target,'')<>''
		  AND COALESCE(s.target_type,'')='token'
		  AND COALESCE(s.module_id,'') IN ($2,$3)
		  AND COALESCE(p.status,'') NOT IN ('canonical_queued','completed')
		ORDER BY s.created_at ASC
		LIMIT $1`, b.batchSize, ModulePumpSybilRadar, ModuleRaydiumPoolGuardian)
	if err != nil {
		if !isUndefinedTableError(err) {
			log.Printf("arvis stream canonical bridge read failed: %v", err)
		}
		return
	}
	defer rows.Close()

	type streamTrigger struct{ id, target, network, moduleID, signature string }
	triggers := []streamTrigger{}
	for rows.Next() {
		var item streamTrigger
		if err := rows.Scan(&item.id, &item.target, &item.network, &item.moduleID, &item.signature); err != nil {
			log.Printf("arvis stream canonical bridge scan failed: %v", err)
			return
		}
		triggers = append(triggers, item)
	}
	if err := rows.Err(); err != nil {
		log.Printf("arvis stream canonical bridge rows failed: %v", err)
		return
	}

	for _, trigger := range triggers {
		if ctx.Err() != nil {
			return
		}
		dedupe := "arvis_stream|" + strings.TrimSpace(trigger.id)
		payload := map[string]any{
			"mint":            trigger.target,
			"network":         trigger.network,
			"mode":            "background_arvis_stream",
			"root_target":     trigger.target,
			"source":          "arvis_stream",
			"source_event_id": trigger.id,
			"source_module":   trigger.moduleID,
			"source_signature": trigger.signature,
			"depth":           0,
			"max_depth":       1,
			"dedupe_key":      dedupe,
		}
		_, _, err := b.jobs.CreateUniqueActive(ctx, jobs.CreateInput{
			Type: canonicalInvestigationJobType, Network: trigger.network, Target: trigger.target, Request: payload,
		}, dedupe)
		if err != nil {
			log.Printf("arvis stream canonical bridge enqueue failed event=%s target=%s: %v", trigger.id, trigger.target, err)
			continue
		}
		_, err = b.db.ExecContext(ctx, `
			INSERT INTO arvis_stream_processing(stream_event_id,target,signature,status,attempts,last_error,processed_at,created_at,updated_at)
			VALUES($1::uuid,$2,$3,'canonical_queued',0,'',now(),now(),now())
			ON CONFLICT(stream_event_id) DO UPDATE SET
				target=EXCLUDED.target,
				signature=EXCLUDED.signature,
				status='canonical_queued',
				last_error='',
				processed_at=now(),
				updated_at=now()`, trigger.id, trigger.target, trigger.signature)
		if err != nil {
			log.Printf("arvis stream canonical bridge mark failed event=%s: %v", trigger.id, err)
		}
	}
}
