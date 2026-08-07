package handlers

import (
	"context"
	"database/sql"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/jobs"
)

const (
	fundingCorpusWarmupSource       = "funding_corpus_warmup"
	fundingCorpusWarmupDefaultLimit = 25
	fundingCorpusWarmupMaximumLimit = 100
)

type ownerFundingCorpusWarmupRequest struct {
	Limit int `json:"limit,omitempty"`
}

type fundingCorpusWarmupCandidate struct {
	Network    string
	Target     string
	LastSeenAt time.Time
}

type fundingCorpusWarmupJobStore interface {
	CreateUniqueActive(context.Context, jobs.CreateInput, string) (jobs.Job, bool, error)
}

type fundingCorpusWarmupResult struct {
	AvailableDistinctTargets int      `json:"available_distinct_targets"`
	RemainingTargets         int      `json:"remaining_unwarmed_targets"`
	RequestedLimit           int      `json:"requested_limit"`
	Enqueued                 int      `json:"enqueued"`
	AlreadyKnown             int      `json:"already_warmed_or_active"`
	JobIDs                   []string `json:"job_ids"`
	Limitations              []string `json:"limitations"`
}

// OwnerWarmFundingCorpus is deliberately owner-triggered. It only enqueues the
// existing canonical investigation job type; the existing JobStore wake signal
// activates the event-driven worker. No scheduler or long-lived connection is
// created here.
func (h *Handler) OwnerWarmFundingCorpus(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DB == nil || h.JobStore == nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Funding corpus warm-up dependencies are unavailable")
		return
	}
	var input ownerFundingCorpusWarmupRequest
	if err := decodeJSON(r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Invalid request body")
		return
	}
	limit := normalizedFundingCorpusWarmupLimit(input.Limit)
	available, remaining, err := fundingCorpusWarmupCounts(r.Context(), h.DB)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Funding corpus warm-up inventory could not be read")
		return
	}
	candidates, err := loadFundingCorpusWarmupCandidates(r.Context(), h.DB, limit*2)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Funding corpus warm-up targets could not be read")
		return
	}
	result := enqueueFundingCorpusWarmupCandidates(r.Context(), h.JobStore, candidates, limit)
	result.AvailableDistinctTargets = available
	result.RemainingTargets = remaining
	result.RequestedLimit = limit
	if remaining == 0 {
		result.Limitations = append(result.Limitations, "Every currently known target already has a completed or active funding-corpus warm-up job.")
	}
	writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "warmup": result})
}

func normalizedFundingCorpusWarmupLimit(value int) int {
	if value <= 0 {
		return fundingCorpusWarmupDefaultLimit
	}
	if value > fundingCorpusWarmupMaximumLimit {
		return fundingCorpusWarmupMaximumLimit
	}
	return value
}

func fundingCorpusWarmupCounts(ctx context.Context, db *sql.DB) (available, remaining int, err error) {
	if db == nil {
		return 0, 0, sql.ErrConnDone
	}
	err = db.QueryRowContext(ctx, fundingCorpusWarmupInventoryCTE+`
		SELECT
			count(*)::integer,
			count(*) FILTER (WHERE NOT EXISTS (
				SELECT 1 FROM web3_jobs j
				WHERE j.job_type=$1
				  AND COALESCE(j.network,'')=COALESCE(c.network,'')
				  AND COALESCE(j.target,'')=COALESCE(c.target,'')
				  AND COALESCE(j.request_payload->>'source','')=$2
				  AND j.status IN ('queued','running','completed')
			))::integer
		FROM candidates c`, CanonicalInvestigationJobType, fundingCorpusWarmupSource).Scan(&available, &remaining)
	return available, remaining, err
}

func loadFundingCorpusWarmupCandidates(ctx context.Context, db *sql.DB, limit int) ([]fundingCorpusWarmupCandidate, error) {
	if db == nil {
		return nil, sql.ErrConnDone
	}
	if limit <= 0 {
		limit = fundingCorpusWarmupDefaultLimit
	}
	rows, err := db.QueryContext(ctx, fundingCorpusWarmupInventoryCTE+`
		SELECT c.network,c.target,c.last_seen_at
		FROM candidates c
		WHERE NOT EXISTS (
			SELECT 1 FROM web3_jobs j
			WHERE j.job_type=$1
			  AND COALESCE(j.network,'')=COALESCE(c.network,'')
			  AND COALESCE(j.target,'')=COALESCE(c.target,'')
			  AND COALESCE(j.request_payload->>'source','')=$2
			  AND j.status IN ('queued','running','completed')
		)
		ORDER BY c.last_seen_at DESC NULLS LAST,c.target ASC
		LIMIT $3`, CanonicalInvestigationJobType, fundingCorpusWarmupSource, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []fundingCorpusWarmupCandidate{}
	for rows.Next() {
		var item fundingCorpusWarmupCandidate
		var lastSeen sql.NullTime
		if err := rows.Scan(&item.Network, &item.Target, &lastSeen); err != nil {
			return nil, err
		}
		item.Network = strings.TrimSpace(item.Network)
		item.Target = strings.TrimSpace(item.Target)
		if lastSeen.Valid {
			item.LastSeenAt = lastSeen.Time.UTC()
		}
		if item.Network == "" {
			item.Network = "solana-mainnet"
		}
		if item.Target != "" {
			out = append(out, item)
		}
	}
	return out, rows.Err()
}

const fundingCorpusWarmupInventoryCTE = `
	WITH source_targets AS (
		SELECT network,btrim(mint) AS target,last_observed_at AS observed_at
		FROM security_actor_token_lifecycle
		WHERE btrim(mint)<>''
		UNION ALL
		SELECT 'solana-mainnet'::text,btrim(mint),created_at
		FROM dossier_exports
		WHERE btrim(mint)<>''
		UNION ALL
		SELECT network,btrim(target_id),last_seen_at
		FROM security_unified_radar_verdicts
		WHERE target_kind='token' AND btrim(target_id)<>''
		UNION ALL
		SELECT network,btrim(mint),last_observed_at
		FROM holder_concentration_observations
		WHERE btrim(mint)<>''
	),
	candidates AS (
		SELECT COALESCE(NULLIF(btrim(network),''),'solana-mainnet') AS network,target,max(observed_at) AS last_seen_at
		FROM source_targets
		WHERE target<>''
		GROUP BY COALESCE(NULLIF(btrim(network),''),'solana-mainnet'),target
	)
`

func enqueueFundingCorpusWarmupCandidates(ctx context.Context, store fundingCorpusWarmupJobStore, candidates []fundingCorpusWarmupCandidate, limit int) fundingCorpusWarmupResult {
	limit = normalizedFundingCorpusWarmupLimit(limit)
	out := fundingCorpusWarmupResult{RequestedLimit: limit, JobIDs: []string{}, Limitations: []string{}}
	if store == nil {
		out.Limitations = append(out.Limitations, "Canonical investigation job store is unavailable.")
		return out
	}
	for _, candidate := range candidates {
		if out.Enqueued >= limit {
			break
		}
		target := strings.TrimSpace(candidate.Target)
		network := strings.TrimSpace(candidate.Network)
		if target == "" {
			continue
		}
		if network == "" {
			network = "solana-mainnet"
		}
		dedupe := strings.Join([]string{fundingCorpusWarmupSource, network, target}, "|")
		payload := canonicalInvestigationJobPayload{
			Mint: target, Network: network, Mode: fundingCorpusWarmupSource,
			RootTarget: target, Source: fundingCorpusWarmupSource,
			// Depth equals MaxDepth so the canonical worker does not recursively
			// expand a bounded warm-up into additional child jobs.
			Depth: 1, MaxDepth: 1, DedupeKey: dedupe,
		}
		job, created, err := store.CreateUniqueActive(ctx, jobs.CreateInput{
			UserID: "owner", Type: CanonicalInvestigationJobType,
			Network: network, Target: target, Request: payload,
		}, dedupe)
		if err != nil {
			out.Limitations = append(out.Limitations, "A known target could not be enqueued: "+compactCanonicalWorkerError(err))
			continue
		}
		if !created {
			out.AlreadyKnown++
			continue
		}
		out.Enqueued++
		out.JobIDs = append(out.JobIDs, job.ID)
	}
	return out
}
