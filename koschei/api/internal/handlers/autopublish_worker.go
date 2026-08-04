package handlers

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

	"koschei/api/internal/workerwake"
)

const (
	autopublishActor         = "autopublish"
	autopublishPublishedBy   = "koschei-autopublish/v1"
	autopublishDrainDelay    = 250 * time.Millisecond
	autopublishErrorBackoff  = 30 * time.Second
	autopublishRedactionMode = "public-onchain-v1"
)

type autopublishWorker struct {
	DB         *sql.DB
	Thresholds autopublishThresholds
	BatchSize  int
	Now        func() time.Time
}

func AutopublishWorkerEnabled() bool {
	if raw := strings.TrimSpace(os.Getenv("KOSCHEI_AUTOPUBLISH_ENABLED")); raw != "" {
		value, err := strconv.ParseBool(raw)
		return err == nil && value
	}
	return false
}

func StartAutopublishWorker(ctx context.Context, db *sql.DB) func() {
	if !AutopublishWorkerEnabled() || db == nil {
		return func() {}
	}
	workerCtx, cancel := context.WithCancel(ctx)
	worker := &autopublishWorker{
		DB:         db,
		Thresholds: defaultAutopublishThresholds(),
		BatchSize:  autopublishEnvInt("KOSCHEI_AUTOPUBLISH_BATCH_SIZE", 25, 1, 200),
		Now:        time.Now,
	}
	go worker.Start(workerCtx)
	log.Printf(
		"dossier autopublish worker started mode=event-driven policy=%s recovery-ceiling=%s batch=%d min-verified=%d max-open=%d max-blocked=%d max-unknown=%d",
		worker.Thresholds.policyVersion(), workerwake.RecoveryCeiling(), worker.BatchSize,
		worker.Thresholds.MinVerifiedRows, worker.Thresholds.MaxOpenRows,
		worker.Thresholds.MaxBlockedRows, worker.Thresholds.MaxUnknownRows,
	)
	return cancel
}

func (w *autopublishWorker) Start(ctx context.Context) {
	if w == nil || w.DB == nil {
		return
	}
	gate := workerwake.Get(workerwake.DossierAutopublish)
	for {
		if ctx.Err() != nil {
			return
		}
		gate.Drain()
		processed, err := w.RunOnce(ctx)
		failed := err != nil && !errors.Is(err, sql.ErrNoRows)
		if failed && ctx.Err() == nil {
			log.Printf("dossier autopublish cycle failed: %v", err)
		}
		if processed > 0 {
			select {
			case <-ctx.Done():
				return
			case <-time.After(autopublishDrainDelay):
			}
			continue
		}
		if failed {
			gate.Wait(ctx, autopublishErrorBackoff)
			continue
		}
		gate.Wait(ctx, workerwake.RecoveryCeiling())
	}
}

type autopublishCandidate struct {
	CaseRef   string
	Canonical []byte
}

func (w *autopublishWorker) RunOnce(ctx context.Context) (int, error) {
	candidates, err := w.loadCandidates(ctx)
	if err != nil {
		return 0, err
	}
	decided := 0
	for _, candidate := range candidates {
		if ctx.Err() != nil {
			return decided, ctx.Err()
		}
		recorded, err := w.decide(ctx, candidate)
		if err != nil {
			log.Printf("dossier autopublish decision failed case_ref=%s: %v", candidate.CaseRef, err)
			continue
		}
		if recorded {
			decided++
		}
	}
	return decided, nil
}

func (w *autopublishWorker) loadCandidates(ctx context.Context) ([]autopublishCandidate, error) {
	policyVersion := w.Thresholds.policyVersion()
	rows, err := w.DB.QueryContext(ctx, `
		SELECT e.case_ref, e.canonical_bundle
		FROM dossier_exports e
		LEFT JOIN dossier_publications p ON p.case_ref = e.case_ref
		LEFT JOIN dossier_autopublish_decisions d
			ON d.case_ref = e.case_ref AND d.policy_version = $1
		WHERE p.case_ref IS NULL
		  AND d.case_ref IS NULL
		ORDER BY e.created_at DESC
		LIMIT $2`, policyVersion, w.BatchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []autopublishCandidate{}
	for rows.Next() {
		var candidate autopublishCandidate
		if err := rows.Scan(&candidate.CaseRef, &candidate.Canonical); err != nil {
			return nil, err
		}
		out = append(out, candidate)
	}
	return out, rows.Err()
}

func (w *autopublishWorker) decide(ctx context.Context, candidate autopublishCandidate) (bool, error) {
	var bundle dossierBundle
	if err := json.Unmarshal(candidate.Canonical, &bundle); err != nil {
		decision := autopublishDecision{
			PolicyVersion: w.Thresholds.policyVersion(),
			Reasons:       []string{"canonical_bundle_unparseable"},
			Thresholds:    w.Thresholds,
		}
		return w.record(ctx, candidate.CaseRef, "sha256:"+strings.Repeat("0", 64), decision)
	}
	decision := evaluateAutopublish(bundle, candidate.CaseRef, w.now(), w.Thresholds)
	bundleHash := strings.TrimSpace(bundle.BundleHash)
	if !autopublishHashPattern.MatchString(bundleHash) {
		bundleHash = "sha256:" + strings.Repeat("0", 64)
	}
	return w.record(ctx, candidate.CaseRef, bundleHash, decision)
}

// record is atomic. The immutable decision row is claimed first. Publication is
// allowed only when this transaction inserted that row; a concurrent worker that
// lost the unique-key race cannot create a second publication event.
func (w *autopublishWorker) record(ctx context.Context, caseRef, bundleHash string, decision autopublishDecision) (bool, error) {
	tx, err := w.DB.BeginTx(ctx, nil)
	if err != nil {
		return false, err
	}
	defer tx.Rollback()

	reasons, err := json.Marshal(decision.Reasons)
	if err != nil {
		return false, err
	}
	counts, err := json.Marshal(decision.Counts)
	if err != nil {
		return false, err
	}
	thresholds, err := json.Marshal(decision.Thresholds.asMap())
	if err != nil {
		return false, err
	}
	policyVersion := strings.TrimSpace(decision.PolicyVersion)
	if policyVersion == "" {
		policyVersion = decision.Thresholds.policyVersion()
	}
	result, err := tx.ExecContext(ctx, `
		INSERT INTO dossier_autopublish_decisions
			(case_ref,policy_version,bundle_hash,published,reasons,counts,thresholds)
		VALUES ($1,$2,$3,$4,$5::jsonb,$6::jsonb,$7::jsonb)
		ON CONFLICT (case_ref,policy_version) DO NOTHING`,
		caseRef, policyVersion, bundleHash, decision.Publish,
		string(reasons), string(counts), string(thresholds))
	if err != nil {
		return false, err
	}
	inserted, err := result.RowsAffected()
	if err != nil {
		return false, err
	}
	if inserted == 0 {
		return false, nil
	}

	if decision.Publish {
		publicationResult, err := tx.ExecContext(ctx, `
			INSERT INTO dossier_publications
				(case_ref,status,public_title,public_summary,featured,redaction_profile,published_at,published_by,created_at,updated_at)
			VALUES ($1,'public',$2,$3,false,$4,now(),$5,now(),now())
			ON CONFLICT (case_ref) DO NOTHING`,
			caseRef, decision.Title, decision.Summary, autopublishRedactionMode, autopublishPublishedBy)
		if err != nil {
			return false, err
		}
		publicationInserted, err := publicationResult.RowsAffected()
		if err != nil {
			return false, err
		}
		if publicationInserted == 0 {
			// An owner or another worker decided while this transaction was open.
			// Roll back the decision claim too; the immutable ledger must never say
			// "published" when no autopublish-owned publication row was inserted.
			return false, nil
		}
		state, err := json.Marshal(map[string]any{
			"status":            "public",
			"featured":          false,
			"public_title":      decision.Title,
			"redaction_profile": autopublishRedactionMode,
			"policy_version":    policyVersion,
			"counts":            decision.Counts,
		})
		if err != nil {
			return false, err
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO dossier_publication_events (case_ref,action,actor,publication_state)
			VALUES ($1,'publish',$2,$3::jsonb)`, caseRef, autopublishActor, string(state)); err != nil {
			return false, err
		}
	}
	if err := tx.Commit(); err != nil {
		return false, err
	}
	return true, nil
}

func (w *autopublishWorker) now() time.Time {
	if w.Now != nil {
		return w.Now().UTC()
	}
	return time.Now().UTC()
}
