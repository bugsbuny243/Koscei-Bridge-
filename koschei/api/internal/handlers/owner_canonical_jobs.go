package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/jobs"
)

type ownerCanonicalJobRequest struct {
	Target   string `json:"target"`
	Address  string `json:"address"`
	Network  string `json:"network"`
	MaxDepth int    `json:"max_depth,omitempty"`
}

func (h *Handler) OwnerCreateCanonicalInvestigationJob(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.JobStore == nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Canonical investigation job store is unavailable")
		return
	}
	var input ownerCanonicalJobRequest
	if err := decodeJSON(r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Invalid request body")
		return
	}
	target := strings.TrimSpace(firstNonEmptyString(input.Target, input.Address))
	if target == "" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "target is required")
		return
	}
	network := strings.TrimSpace(input.Network)
	if network == "" {
		network = "solana-mainnet"
	}
	maxDepth := input.MaxDepth
	if maxDepth <= 0 {
		maxDepth = canonicalWorkerEnvInt("ACTOR_RECURSIVE_MAX_DEPTH", 1, 1, 3)
	}
	if maxDepth > 3 {
		maxDepth = 3
	}
	classification := classifyRadarTarget(r.Context(), target)
	resolvedTarget := target
	if classification.Type == radarTargetTokenAccount && strings.TrimSpace(classification.TokenOwnerWallet) != "" {
		resolvedTarget = strings.TrimSpace(classification.TokenOwnerWallet)
	}
	switch classification.Type {
	case radarTargetTokenMint, radarTargetWallet, radarTargetTokenAccount:
	default:
		writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
			"ok": false, "error": "unsupported_canonical_job_target",
			"target": target, "target_classification": classification,
			"message": "Kalıcı soruşturma işi doğrulanmış token mint, wallet veya token-account hedefini kabul eder.",
		})
		return
	}
	bucket := time.Now().UTC().Truncate(30 * time.Second)
	dedupe := strings.Join([]string{"owner_manual", resolvedTarget, bucket.Format(time.RFC3339)}, "|")
	payload := canonicalInvestigationJobPayload{
		Address: resolvedTarget, Network: network, Mode: "owner_manual_canonical_job",
		RootTarget: resolvedTarget, Source: "owner_command_center",
		Depth: 0, MaxDepth: maxDepth, DedupeKey: dedupe,
	}
	if classification.Type == radarTargetTokenMint {
		payload.Mint, payload.Address = resolvedTarget, ""
	}
	job, created, err := h.JobStore.CreateUniqueActive(r.Context(), jobs.CreateInput{
		UserID: "owner", Email: "", Type: CanonicalInvestigationJobType,
		Network: network, Target: resolvedTarget, Request: payload,
	}, dedupe)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, APICodeInternalError, "Canonical investigation job could not be created")
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]any{
		"ok": true, "created": created, "job": canonicalOwnerJobResponse(job),
		"target": target, "resolved_target": resolvedTarget,
		"target_classification": classification,
		"poll_url":              "/api/owner/radar/jobs/" + job.ID,
	})
}

func (h *Handler) OwnerGetCanonicalInvestigationJob(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.JobStore == nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Canonical investigation job store is unavailable")
		return
	}
	id := lastCanonicalJobPathSegment(r.URL.Path)
	if id == "" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "job id is required")
		return
	}
	job, err := h.JobStore.Get(r.Context(), id, "")
	if err != nil {
		writeAPIError(w, http.StatusNotFound, APICodeNotFound, "Job not found")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "job": canonicalOwnerJobResponse(job)})
}

func canonicalOwnerJobResponse(job jobs.Job) map[string]any {
	out := map[string]any{
		"id":         job.ID,
		"job_type":   job.Type,
		"status":     job.Status,
		"network":    job.Network,
		"target":     job.Target,
		"progress":   job.Progress,
		"attempts":   job.Attempts,
		"queued_at":  job.QueuedAt,
		"updated_at": job.UpdatedAt,
	}
	if len(job.ResultPayload) > 0 && string(job.ResultPayload) != "null" {
		var result any
		if json.Unmarshal(job.ResultPayload, &result) == nil {
			out["result"] = result
		}
	}
	if strings.TrimSpace(job.ErrorCode) != "" {
		out["error_code"] = job.ErrorCode
		out["error_message"] = job.ErrorMessage
	}
	return out
}

func lastCanonicalJobPathSegment(value string) string {
	parts := strings.Split(strings.Trim(strings.TrimSpace(value), "/"), "/")
	if len(parts) == 0 {
		return ""
	}
	id := strings.TrimSpace(parts[len(parts)-1])
	if id == "jobs" || id == "radar" {
		return ""
	}
	return id
}
