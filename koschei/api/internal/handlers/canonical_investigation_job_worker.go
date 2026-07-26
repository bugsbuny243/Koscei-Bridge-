package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/jobs"
	"koschei/api/internal/services"
	"koschei/api/internal/web3"
	"koschei/api/internal/workerwake"
)

const (
	CanonicalInvestigationJobType = "canonical_investigation"
	legacyTokenScanJobType        = "token_scan"
)

type canonicalInvestigationJobPayload struct {
	Mint          string `json:"mint,omitempty"`
	Address       string `json:"address,omitempty"`
	Network       string `json:"network,omitempty"`
	Mode          string `json:"mode,omitempty"`
	RootTarget    string `json:"root_target,omitempty"`
	RootJobID     string `json:"root_job_id,omitempty"`
	ParentTarget  string `json:"parent_target,omitempty"`
	ParentActor   string `json:"parent_actor,omitempty"`
	Source        string `json:"source,omitempty"`
	SourceEventID string `json:"source_event_id,omitempty"`
	Depth         int    `json:"depth,omitempty"`
	MaxDepth      int    `json:"max_depth,omitempty"`
	DedupeKey     string `json:"dedupe_key,omitempty"`
}

type canonicalInvestigationChildQueue struct {
	Depth              int      `json:"depth"`
	MaxDepth           int      `json:"max_depth"`
	CandidatesObserved int      `json:"candidates_observed"`
	CandidatesEligible int      `json:"candidates_eligible"`
	JobsCreated        int      `json:"jobs_created"`
	JobsDeduplicated   int      `json:"jobs_deduplicated"`
	JobIDs             []string `json:"job_ids"`
	DeferredMints      []string `json:"deferred_mints"`
	Limitations        []string `json:"limitations"`
}

// canonicalWorkerDrainDelay is the settle delay between two claimed jobs. It
// keeps a queued burst draining quickly without a busy loop.
const canonicalWorkerDrainDelay = 10 * time.Millisecond

// canonicalWorkerErrorBackoff is the retry delay after a failed claim. It is
// short enough that a queued job is not stranded and long enough that a database
// outage does not become a hot retry loop.
const canonicalWorkerErrorBackoff = 5 * time.Second

type canonicalInvestigationJobWorker struct {
	Handler *Handler
	Store   *jobs.Store
	// PollEvery no longer drives idle frequency (#697); it is retained as the
	// configured upper bound reported at startup for operator visibility.
	PollEvery  time.Duration
	StaleAfter time.Duration
	Heartbeat  time.Duration
	ChildLimit int
}

func CanonicalInvestigationJobWorkerEnabled() bool {
	if raw := strings.TrimSpace(os.Getenv("KOSCHEI_CANONICAL_JOB_WORKER_ENABLED")); raw != "" {
		value, err := strconv.ParseBool(raw)
		return err == nil && value
	}
	return strings.EqualFold(strings.TrimSpace(os.Getenv("APP_ENV")), "production")
}

// StartCanonicalInvestigationJobWorker starts a database-backed consumer. It has
// no investigation-wide timeout: shutdown cancels it, while individual network
// calls retain their own bounded timeouts and retry semantics.
func StartCanonicalInvestigationJobWorker(ctx context.Context, db, readDB *sql.DB, solanaRPC *web3.SolanaRPC, store *jobs.Store) func() {
	if !CanonicalInvestigationJobWorkerEnabled() || db == nil {
		return func() {}
	}
	if store == nil {
		store = jobs.NewStore(db)
	}
	workerCtx, cancel := context.WithCancel(ctx)
	worker := &canonicalInvestigationJobWorker{
		Handler:    &Handler{DB: db, DBRead: readDB, SolanaRPC: solanaRPC, JobStore: store},
		Store:      store,
		PollEvery:  time.Duration(canonicalWorkerEnvInt("KOSCHEI_CANONICAL_JOB_POLL_SECONDS", 2, 1, 60)) * time.Second,
		StaleAfter: time.Duration(canonicalWorkerEnvInt("KOSCHEI_CANONICAL_JOB_STALE_SECONDS", 7200, 300, 86400)) * time.Second,
		Heartbeat:  time.Duration(canonicalWorkerEnvInt("KOSCHEI_CANONICAL_JOB_HEARTBEAT_SECONDS", 30, 10, 300)) * time.Second,
		ChildLimit: canonicalWorkerEnvInt("ACTOR_CHILD_MINT_JOB_LIMIT", 40, 1, 200),
	}
	go worker.Start(workerCtx)
	log.Printf("canonical investigation job worker started mode=event-driven recovery-ceiling=%s stale=%s concurrency=1", workerwake.RecoveryCeiling(), worker.StaleAfter)
	return cancel
}

func (w *canonicalInvestigationJobWorker) Start(ctx context.Context) {
	if w == nil || w.Store == nil || w.Handler == nil {
		return
	}
	if recovered, err := w.Store.RequeueStale(ctx, w.StaleAfter); err != nil {
		log.Printf("canonical investigation stale-job recovery failed: %v", err)
	} else if recovered > 0 {
		log.Printf("canonical investigation stale-job recovery affected=%d", recovered)
	}
	// Event-driven idle (#697). web3_jobs rows are claimable as soon as they are
	// queued, so there is no future schedule to compute: when a claim finds
	// nothing, the worker sleeps until an in-process enqueue signal arrives or the
	// bounded recovery ceiling elapses. A processed job is followed by a very
	// short settle delay so a queued burst drains without waiting on signals.
	gate := workerwake.Get(workerwake.CanonicalInvestigation)
	for {
		if ctx.Err() != nil {
			return
		}
		gate.Drain()
		processed, err := w.RunOnce(ctx)
		failed := err != nil && !errors.Is(err, sql.ErrNoRows)
		if failed && ctx.Err() == nil {
			log.Printf("canonical investigation worker cycle failed: %v", err)
		}
		if processed {
			select {
			case <-ctx.Done():
				return
			case <-time.After(canonicalWorkerDrainDelay):
			}
			continue
		}
		// A claim failure is not an empty queue: retry on a short backoff instead
		// of parking for the full recovery ceiling, so a transient database error
		// cannot strand a queued job for minutes.
		if failed {
			gate.Wait(ctx, canonicalWorkerErrorBackoff)
			continue
		}
		gate.Wait(ctx, workerwake.RecoveryCeiling())
	}
}

func (w *canonicalInvestigationJobWorker) RunOnce(ctx context.Context) (bool, error) {
	job, err := w.Store.ClaimNext(ctx, CanonicalInvestigationJobType, legacyTokenScanJobType)
	if err != nil {
		return false, err
	}
	jobCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	heartbeatDone := make(chan struct{})
	go func() {
		ticker := time.NewTicker(w.Heartbeat)
		defer ticker.Stop()
		defer close(heartbeatDone)
		for {
			select {
			case <-jobCtx.Done():
				return
			case <-ticker.C:
				_ = w.Store.UpdateProgress(jobCtx, job.ID, 20)
			}
		}
	}()

	result, processErr := w.processJob(jobCtx, job)
	cancel()
	<-heartbeatDone
	if processErr != nil {
		status, retryErr := w.Store.RetryOrFail(ctx, job.ID, "CANONICAL_INVESTIGATION_FAILED", compactCanonicalWorkerError(processErr))
		if retryErr != nil {
			return true, retryErr
		}
		log.Printf("canonical investigation job %s target=%s status=%s error=%v", job.ID, job.Target, status, processErr)
		return true, nil
	}
	if err := w.Store.Complete(ctx, job.ID, result); err != nil {
		return true, err
	}
	log.Printf("canonical investigation job completed id=%s target=%s", job.ID, job.Target)
	return true, nil
}

func (w *canonicalInvestigationJobWorker) processJob(ctx context.Context, job jobs.Job) (map[string]any, error) {
	payload := canonicalInvestigationJobPayload{}
	if len(job.RequestPayload) > 0 && string(job.RequestPayload) != "null" {
		if err := json.Unmarshal(job.RequestPayload, &payload); err != nil {
			return nil, fmt.Errorf("decode canonical job payload: %w", err)
		}
	}
	target := strings.TrimSpace(firstNonEmptyString(payload.Mint, payload.Address, job.Target))
	if target == "" {
		return nil, fmt.Errorf("canonical job target is required")
	}
	network := strings.TrimSpace(firstNonEmptyString(payload.Network, job.Network, "solana-mainnet"))
	classification := classifyRadarTarget(ctx, target)
	mode := strings.TrimSpace(payload.Mode)
	if mode == "" {
		mode = "background_canonical_investigation"
	}
	_ = w.Store.UpdateProgress(ctx, job.ID, 12)

	var report map[string]any
	switch classification.Type {
	case radarTargetTokenMint:
		assembly := w.Handler.buildUnifiedInvestigationReport(ctx, target, network, mode)
		_ = w.Store.UpdateProgress(ctx, job.ID, 75)
		if services.SecurityRadarHasLiveEvidence(assembly.Core.Bundle) {
			if err := w.Handler.saveSecurityRadarBundle(ctx, "system:canonical_job_worker", mode, assembly.Core.Bundle); err != nil {
				return nil, fmt.Errorf("persist canonical radar bundle: %w", err)
			}
		}
		behaviorPersistence := "not_applicable"
		if assembly.Store != nil && len(assembly.Behavior.Evidence) > 0 {
			behaviorPersistence = "persisted"
			for _, item := range assembly.Behavior.Evidence {
				item.Network = network
				if err := assembly.Store.UpsertEvidence(ctx, item); err != nil {
					behaviorPersistence = "partial_failure"
				}
			}
		}
		unifiedPersistence, unifiedHistory := w.Handler.persistUnifiedRadarVerdict(
			ctx, assembly.DB, network, "token", target, assembly.UnifiedVerdict, assembly.Behavior,
		)
		report = assembly.Report
		report["final_verdict_persistence"] = unifiedPersistence
		report["final_verdict_history"] = unifiedHistory
		report["behavior_evidence_persistence"] = behaviorPersistence
		attachCanonicalInvestigationDiagnostics(report)
	case radarTargetWallet:
		var err error
		report, err = w.Handler.buildUnifiedWalletInvestigationReport(ctx, target, target, network, true)
		if err != nil {
			return nil, fmt.Errorf("build canonical wallet investigation: %w", err)
		}
		_ = w.Store.UpdateProgress(ctx, job.ID, 75)
	case radarTargetTokenAccount:
		wallet := strings.TrimSpace(classification.TokenOwnerWallet)
		if wallet == "" {
			return nil, fmt.Errorf("token account owner wallet could not be resolved")
		}
		var err error
		report, err = w.Handler.buildUnifiedWalletInvestigationReport(ctx, target, wallet, network, true)
		if err != nil {
			return nil, fmt.Errorf("build token-account owner investigation: %w", err)
		}
		_ = w.Store.UpdateProgress(ctx, job.ID, 75)
	default:
		return nil, fmt.Errorf("canonical worker supports token mint, wallet or token account; classification=%s", classification.Type)
	}

	rootJobID := strings.TrimSpace(firstNonEmptyString(payload.RootJobID, job.ID))
	report["target_classification"] = classification
	report["background_job"] = map[string]any{
		"job_id": job.ID, "root_job_id": rootJobID, "job_type": job.Type, "attempt": job.Attempts,
		"source": payload.Source, "source_event_id": payload.SourceEventID,
		"root_target":   firstNonEmptyString(payload.RootTarget, target),
		"parent_target": payload.ParentTarget, "parent_actor": payload.ParentActor,
		"depth": payload.Depth, "max_depth": canonicalPayloadMaxDepth(payload),
	}
	childQueue := w.scheduleCreatedMintChildren(ctx, job, payload, rootJobID, report)
	report["recursive_child_queue"] = childQueue
	return report, nil
}

func (w *canonicalInvestigationJobWorker) scheduleCreatedMintChildren(ctx context.Context, parent jobs.Job, payload canonicalInvestigationJobPayload, rootJobID string, report map[string]any) canonicalInvestigationChildQueue {
	maxDepth := canonicalPayloadMaxDepth(payload)
	out := canonicalInvestigationChildQueue{
		Depth: payload.Depth, MaxDepth: maxDepth,
		JobIDs: []string{}, DeferredMints: []string{}, Limitations: []string{},
	}
	if payload.Depth >= maxDepth {
		out.Limitations = append(out.Limitations, "Recursive child scheduling reached the configured investigation depth; discovered evidence remains in the dossier.")
		return out
	}
	actor := canonicalMap(report["actor_investigation"])
	external := canonicalMap(actor["external_discovery"])
	portfolio := canonicalMap(external["created_mint_portfolio"])
	candidates := canonicalSlice(portfolio["verified_candidates"])
	out.CandidatesObserved = len(candidates)
	rootTarget := strings.TrimSpace(firstNonEmptyString(payload.RootTarget, parent.Target))
	rootJobID = strings.TrimSpace(firstNonEmptyString(rootJobID, payload.RootJobID, parent.ID))
	seen := map[string]bool{}
	for _, raw := range candidates {
		candidate := canonicalMap(raw)
		mint := strings.TrimSpace(canonicalString(candidate["mint"]))
		if mint == "" || strings.EqualFold(mint, parent.Target) || seen[mint] {
			continue
		}
		seen[mint] = true
		out.CandidatesEligible++
		if out.JobsCreated+out.JobsDeduplicated >= w.ChildLimit {
			out.DeferredMints = append(out.DeferredMints, mint)
			continue
		}
		childDepth := payload.Depth + 1
		dedupe := strings.Join([]string{rootJobID, rootTarget, strconv.Itoa(childDepth), mint}, "|")
		childPayload := canonicalInvestigationJobPayload{
			Mint: mint, Network: parent.Network, Mode: "background_recursive_token_scan",
			RootTarget: rootTarget, RootJobID: rootJobID, ParentTarget: parent.Target,
			ParentActor: strings.TrimSpace(canonicalString(actor["wallet"])),
			Source:      "created_mint_portfolio", Depth: childDepth, MaxDepth: maxDepth, DedupeKey: dedupe,
		}
		child, created, err := w.Store.CreateUniqueActive(ctx, jobs.CreateInput{
			UserID: parent.UserID, Email: parent.Email, Type: CanonicalInvestigationJobType,
			Network: parent.Network, Target: mint, Request: childPayload,
		}, dedupe)
		if err != nil {
			out.Limitations = append(out.Limitations, "Child mint job could not be queued for "+mint+": "+compactCanonicalWorkerError(err))
			continue
		}
		out.JobIDs = append(out.JobIDs, child.ID)
		if created {
			out.JobsCreated++
		} else {
			out.JobsDeduplicated++
		}
	}
	if len(out.DeferredMints) > 0 {
		out.Limitations = append(out.Limitations, fmt.Sprintf("%d verified created mints were deferred by the per-parent queue batch; they remain preserved in actor evidence.", len(out.DeferredMints)))
	}
	return out
}

func canonicalPayloadMaxDepth(payload canonicalInvestigationJobPayload) int {
	if payload.MaxDepth > 0 {
		if payload.MaxDepth > 3 {
			return 3
		}
		return payload.MaxDepth
	}
	return canonicalWorkerEnvInt("ACTOR_RECURSIVE_MAX_DEPTH", 1, 1, 3)
}

func canonicalWorkerEnvInt(name string, fallback, minValue, maxValue int) int {
	value, err := strconv.Atoi(strings.TrimSpace(os.Getenv(name)))
	if err != nil {
		return fallback
	}
	if value < minValue {
		return minValue
	}
	if value > maxValue {
		return maxValue
	}
	return value
}

func compactCanonicalWorkerError(err error) string {
	if err == nil {
		return "unknown error"
	}
	value := strings.TrimSpace(err.Error())
	if len(value) > 500 {
		value = value[:500]
	}
	return value
}
