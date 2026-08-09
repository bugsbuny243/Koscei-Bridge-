package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log"
	"os"
	"strconv"
	"strings"
	"time"
)

const (
	securityRadarIngestModeLegacy  = "legacy"
	securityRadarIngestModeJournal = "journal"
)

type securityRadarJournalStreamWorker struct {
	Store              *SecurityRadarStore
	WSSURL             string
	RPCURL             string
	Network            string
	Queue              chan SecurityRadarStreamEventRecord
	PersistConcurrency int
	EnrichmentBatch    int
	decoder            *SecurityRadarStreamWorker
}

type securityRadarEnrichmentTarget struct {
	ID        string
	Signature string
	Network   string
	ModuleID  string
	Attempts  int
}

// StartSecurityRadarSovereignStreamIfEnabled keeps the legacy collector as the
// default while allowing an opt-in durable-first journal mode. Journal mode
// separates ingestion from RPC enrichment and verdict production: the WSS
// reader only decodes and queues raw observations, persistence workers commit
// them to the stream ledger, and a separate enrichment loop resolves token
// targets for the existing ARVIS stream verdict worker.
func StartSecurityRadarSovereignStreamIfEnabled(ctx context.Context, db *sql.DB) func() {
	mode := securityRadarStreamIngestMode()
	if mode != securityRadarIngestModeJournal {
		if mode != securityRadarIngestModeLegacy {
			log.Printf("security radar ingest mode %q is unsupported; falling back to legacy WSS collector", mode)
		}
		return StartSecurityRadarStreamIfEnabled(ctx, db)
	}
	if db == nil || !securityRadarStreamEnabled() {
		return func() {}
	}
	wssURL := resolveSecurityRadarWSSURL()
	if wssURL == "" {
		log.Printf("security radar sovereign journal not started: no WSS URL could be resolved")
		return func() {}
	}
	ctx, cancel := context.WithCancel(ctx)
	worker := newSecurityRadarJournalStreamWorker(NewSecurityRadarStore(db), wssURL, resolveSecurityRadarRPCURL())
	go worker.Start(ctx)
	return cancel
}

func securityRadarStreamIngestMode() string {
	mode := strings.ToLower(strings.TrimSpace(os.Getenv("KOSCHEI_STREAM_INGEST_MODE")))
	if mode == "" {
		return securityRadarIngestModeLegacy
	}
	return mode
}

func newSecurityRadarJournalStreamWorker(store *SecurityRadarStore, wssURL, rpcURL string) *securityRadarJournalStreamWorker {
	bufferSize := boundedSecurityRadarEnvInt("RADAR_EVENT_BUFFER_SIZE", 5000, 1, 100000)
	persistConcurrency := boundedSecurityRadarEnvInt("KOSCHEI_STREAM_JOURNAL_WRITERS", 4, 1, 32)
	enrichmentBatch := boundedSecurityRadarEnvInt("KOSCHEI_STREAM_ENRICHMENT_BATCH", 25, 1, 100)
	decoder := NewSecurityRadarStreamWorker(store, wssURL, rpcURL)
	return &securityRadarJournalStreamWorker{
		Store:              store,
		WSSURL:             strings.TrimSpace(wssURL),
		RPCURL:             strings.TrimSpace(rpcURL),
		Network:            firstRadarValue(os.Getenv("RADAR_STREAM_NETWORK"), "solana-mainnet"),
		Queue:              make(chan SecurityRadarStreamEventRecord, bufferSize),
		PersistConcurrency: persistConcurrency,
		EnrichmentBatch:    enrichmentBatch,
		decoder:            decoder,
	}
}

func boundedSecurityRadarEnvInt(key string, fallback, minValue, maxValue int) int {
	raw := strings.TrimSpace(os.Getenv(key))
	if raw == "" {
		return fallback
	}
	parsed, err := strconv.Atoi(raw)
	if err != nil || parsed < minValue || parsed > maxValue {
		return fallback
	}
	return parsed
}

func (w *securityRadarJournalStreamWorker) Start(ctx context.Context) {
	if w == nil || w.Store == nil || w.Store.DB == nil || strings.TrimSpace(w.WSSURL) == "" {
		return
	}
	log.Printf("security radar sovereign journal started provider=%s mode=%s network=%s writers=%d backpressure=block_not_drop", SecurityRadarStreamProvider, SecurityRadarStreamModeLogs, w.Network, w.PersistConcurrency)
	for i := 0; i < w.PersistConcurrency; i++ {
		go w.persistLoop(ctx)
	}
	if strings.TrimSpace(w.RPCURL) != "" {
		go w.enrichmentLoop(ctx)
	} else {
		log.Printf("security radar sovereign enrichment paused: no RPC URL resolved; raw stream journal remains active")
	}

	backoff := 3 * time.Second
	for {
		select {
		case <-ctx.Done():
			log.Printf("security radar sovereign journal stopped")
			return
		default:
		}
		startedAt := time.Now()
		err := w.runOnce(ctx)
		if ctx.Err() != nil {
			return
		}
		if time.Since(startedAt) >= 45*time.Second {
			backoff = 3 * time.Second
		}
		if isRadarRateLimitError(err) && backoff < 30*time.Second {
			backoff = 30 * time.Second
		}
		wait := radarReconnectWait(backoff)
		if err != nil {
			log.Printf("security radar sovereign reconnect scheduled retry_in=%s err=%s", wait.Round(time.Second), safeProviderError(err))
		}
		if backoff < 2*time.Minute {
			backoff *= 2
			if backoff > 2*time.Minute {
				backoff = 2 * time.Minute
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(wait):
		}
	}
}

func (w *securityRadarJournalStreamWorker) runOnce(ctx context.Context) error {
	conn, err := dialMinimalWebSocket(ctx, w.WSSURL)
	if err != nil {
		return err
	}
	defer conn.Close()
	for index, source := range arvisHeartbeatSources() {
		programID := strings.TrimSpace(source.ProgramID)
		if programID == "" {
			continue
		}
		subscription := map[string]any{"jsonrpc": "2.0", "id": index + 1, "method": "logsSubscribe", "params": []any{map[string]any{"mentions": []string{programID}}, map[string]any{"commitment": "confirmed"}}}
		if err := conn.WriteJSON(subscription); err != nil {
			return err
		}
	}
	ping := time.NewTicker(25 * time.Second)
	defer ping.Stop()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ping.C:
			_ = conn.Ping()
		default:
		}
		payload, err := conn.ReadText(ctx)
		if err != nil {
			return err
		}
		event, ok := w.decoder.decodeLogsPayload(payload)
		if !ok {
			continue
		}
		if err := enqueueSecurityRadarJournalEvent(ctx, w.Queue, event); err != nil {
			return err
		}
	}
}

// enqueueSecurityRadarJournalEvent intentionally has no default/drop branch.
// Backpressure blocks intake until journal capacity returns or the context is
// cancelled, so an in-process overload cannot silently evict an observation.
func enqueueSecurityRadarJournalEvent(ctx context.Context, queue chan<- SecurityRadarStreamEventRecord, event SecurityRadarStreamEventRecord) error {
	select {
	case queue <- event:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (w *securityRadarJournalStreamWorker) persistLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case event := <-w.Queue:
			if _, err := w.Store.InsertStreamEvent(ctx, event); err != nil && ctx.Err() == nil {
				log.Printf("security radar sovereign journal insert failed: %v", err)
			}
		}
	}
}

func (w *securityRadarJournalStreamWorker) enrichmentLoop(ctx context.Context) {
	w.enrichBatch(ctx)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			w.enrichBatch(ctx)
		}
	}
}

func (w *securityRadarJournalStreamWorker) enrichBatch(ctx context.Context) {
	targets, err := w.claimEnrichmentBatch(ctx, w.EnrichmentBatch)
	if err != nil {
		if !isUndefinedTableError(err) && ctx.Err() == nil {
			log.Printf("security radar sovereign enrichment claim failed: %v", err)
		}
		return
	}
	for _, target := range targets {
		if ctx.Err() != nil {
			return
		}
		w.enrichOne(ctx, target)
	}
}

func (w *securityRadarJournalStreamWorker) claimEnrichmentBatch(ctx context.Context, limit int) ([]securityRadarEnrichmentTarget, error) {
	if w == nil || w.Store == nil || w.Store.DB == nil {
		return nil, errors.New("security radar store unavailable")
	}
	if limit <= 0 || limit > 100 {
		limit = 25
	}
	rows, err := w.Store.DB.QueryContext(ctx, `
        WITH candidates AS (
            SELECT id
            FROM security_radar_stream_events
            WHERE signature IS NOT NULL
              AND btrim(signature)<>''
              AND module_id IN ($1,$2)
              AND (target IS NULL OR btrim(target)='' OR target=signature OR target_type<>'token')
              AND COALESCE((decoded->>'sovereign_enrichment_attempts')::integer,0) < 5
              AND (
                    NOT (decoded ? 'sovereign_enrichment_status')
                    OR updated_at < now() - interval '30 seconds'
                  )
            ORDER BY created_at ASC
            FOR UPDATE SKIP LOCKED
            LIMIT $3
        )
        UPDATE security_radar_stream_events s
        SET decoded=jsonb_set(
                s.decoded || jsonb_build_object(
                    'sovereign_enrichment_status','processing',
                    'sovereign_enrichment_attempted_at',now()::text
                ),
                '{sovereign_enrichment_attempts}',
                to_jsonb(COALESCE((s.decoded->>'sovereign_enrichment_attempts')::integer,0)+1),
                true
            ),
            updated_at=now()
        FROM candidates c
        WHERE s.id=c.id
        RETURNING s.id::text,COALESCE(s.signature,''),COALESCE(s.network,'solana-mainnet'),COALESCE(s.module_id,''),
                  COALESCE((s.decoded->>'sovereign_enrichment_attempts')::integer,1)
    `, ModulePumpSybilRadar, ModuleRaydiumPoolGuardian, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []securityRadarEnrichmentTarget{}
	for rows.Next() {
		var target securityRadarEnrichmentTarget
		if err := rows.Scan(&target.ID, &target.Signature, &target.Network, &target.ModuleID, &target.Attempts); err != nil {
			return nil, err
		}
		out = append(out, target)
	}
	return out, rows.Err()
}

func (w *securityRadarJournalStreamWorker) enrichOne(ctx context.Context, target securityRadarEnrichmentTarget) {
	attemptCtx, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	tx, err := SolanaGetTransactionJSONParsed(attemptCtx, w.RPCURL, target.Signature)
	if err != nil {
		w.markEnrichmentFailure(ctx, target, compactRadarError("getTransaction", err))
		return
	}
	mints := extractMintsFromTransactionMap(map[string]any(tx))
	if len(mints) == 0 {
		w.markEnrichmentFailure(ctx, target, "getTransaction returned no token mint")
		return
	}
	encodedMints, _ := json.Marshal(mints)
	_, err = w.Store.DB.ExecContext(ctx, `
        UPDATE security_radar_stream_events
        SET target=$2,
            target_type='token',
            evidence_quality='transaction_enriched_mint',
            decoded=decoded || jsonb_build_object(
                'enriched_mint',$2,
                'enriched_mints',$3::jsonb,
                'sovereign_enrichment_status','completed',
                'sovereign_enrichment_completed_at',now()::text
            ),
            updated_at=now()
        WHERE id=$1::uuid
    `, target.ID, mints[0], string(encodedMints))
	if err != nil && ctx.Err() == nil {
		log.Printf("security radar sovereign enrichment update failed event=%s: %v", target.ID, err)
	}
}

func (w *securityRadarJournalStreamWorker) markEnrichmentFailure(ctx context.Context, target securityRadarEnrichmentTarget, message string) {
	if w == nil || w.Store == nil || w.Store.DB == nil {
		return
	}
	status := "retryable"
	if target.Attempts >= 5 {
		status = "exhausted"
	}
	if len(message) > 500 {
		message = message[:500]
	}
	_, err := w.Store.DB.ExecContext(ctx, `
        UPDATE security_radar_stream_events
        SET decoded=decoded || jsonb_build_object(
                'sovereign_enrichment_status',$2,
                'sovereign_enrichment_error',$3,
                'sovereign_enrichment_failed_at',now()::text
            ),
            updated_at=now()
        WHERE id=$1::uuid
    `, target.ID, status, strings.TrimSpace(message))
	if err != nil && ctx.Err() == nil {
		log.Printf("security radar sovereign enrichment failure state update failed event=%s: %v", target.ID, err)
	}
}
