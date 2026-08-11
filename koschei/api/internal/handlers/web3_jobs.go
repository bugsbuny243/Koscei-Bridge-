package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"

	"koschei/api/internal/jobs"
)

type asyncWeb3Request struct {
	Mint      string `json:"mint"`
	Address   string `json:"address"`
	Signature string `json:"signature"`
	Network   string `json:"network"`
	MaxDepth  int    `json:"max_depth,omitempty"`
}

func (h *Handler) CreateWeb3Job(w http.ResponseWriter, r *http.Request) {
	if h.JobStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "job service unavailable"})
		return
	}
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	jobType := web3JobTypeFromPath(r.URL.Path)
	if jobType == "" {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "unknown job type"})
		return
	}
	var req asyncWeb3Request
	if err := decodeJSON(r, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_body"})
		return
	}
	if req.Network == "" {
		req.Network = defaultNetworkForJob(jobType)
	}
	target := strings.TrimSpace(req.Mint)
	if target == "" {
		target = strings.TrimSpace(req.Address)
	}
	if target == "" {
		target = strings.TrimSpace(req.Signature)
	}
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "target required"})
		return
	}
	if _, err := h.requirePremiumOutput(claims.Sub); err != nil {
		writeJSON(w, http.StatusPaymentRequired, insufficientOutputsResponse())
		return
	}
	requestPayload := any(req)
	if jobType == CanonicalInvestigationJobType {
		classification := classifyRadarTarget(r.Context(), target)
		resolvedTarget := target
		if classification.Type == radarTargetTokenAccount && strings.TrimSpace(classification.TokenOwnerWallet) != "" {
			resolvedTarget = strings.TrimSpace(classification.TokenOwnerWallet)
		}
		switch classification.Type {
		case radarTargetTokenMint, radarTargetWallet, radarTargetTokenAccount:
		default:
			writeJSON(w, http.StatusUnprocessableEntity, map[string]any{
				"error": "unsupported_canonical_job_target", "target_classification": classification,
			})
			return
		}
		maxDepth := req.MaxDepth
		if maxDepth <= 0 {
			maxDepth = canonicalWorkerEnvInt("ACTOR_RECURSIVE_MAX_DEPTH", 1, 1, 3)
		}
		payload := canonicalInvestigationJobPayload{
			Address: resolvedTarget, Network: req.Network, Mode: "customer_canonical_job",
			RootTarget: resolvedTarget, Source: "customer_radar_job", Depth: 0, MaxDepth: maxDepth,
		}
		if classification.Type == radarTargetTokenMint {
			payload.Mint, payload.Address = resolvedTarget, ""
		}
		target, requestPayload = resolvedTarget, payload
	}
	job, err := h.JobStore.Create(r.Context(), jobs.CreateInput{
		UserID: claims.Sub, Email: claims.Email, Type: jobType,
		Network: req.Network, Target: target, Request: requestPayload,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "job create failed"})
		return
	}
	if h.JobQueue != nil {
		_ = h.JobQueue.Publish(job)
	}
	pollURL := "/api/jobs/" + job.ID
	if jobType == CanonicalInvestigationJobType {
		pollURL = "/api/v1/radar/jobs/" + job.ID
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"job_id": job.ID, "status": job.Status, "poll_url": pollURL,
		"package_required": true, "canonical_engine": jobType == CanonicalInvestigationJobType,
	})
}

func (h *Handler) GetWeb3Job(w http.ResponseWriter, r *http.Request) {
	if h.JobStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "job service unavailable"})
		return
	}
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	id := lastCanonicalJobPathSegment(r.URL.Path)
	if id == "" {
		h.CustomerInvestigationHistory(w, r)
		return
	}
	job, err := h.JobStore.Get(r.Context(), id, claims.Sub)
	if err == sql.ErrNoRows {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "job not found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "job read failed"})
		return
	}
	resp := map[string]any{
		"id": job.ID, "job_type": job.Type, "status": job.Status,
		"network": job.Network, "target": job.Target, "progress": job.Progress,
		"attempts": job.Attempts, "queued_at": job.QueuedAt, "updated_at": job.UpdatedAt,
	}
	if len(job.ResultPayload) > 0 && string(job.ResultPayload) != "null" {
		var raw any
		if json.Unmarshal(job.ResultPayload, &raw) == nil {
			resp["result"] = raw
		}
	}
	if job.ErrorCode != "" {
		resp["error_code"] = job.ErrorCode
		resp["error_message"] = job.ErrorMessage
	}
	writeJSON(w, http.StatusOK, resp)
}

func web3JobTypeFromPath(path string) string {
	path = strings.Trim(strings.TrimSpace(path), "/")
	if path == "api/v1/radar/jobs" {
		return CanonicalInvestigationJobType
	}
	value := strings.TrimPrefix(path, "api/jobs/")
	switch strings.Trim(value, "/") {
	case "token-scan":
		return legacyTokenScanJobType
	case "wallet-score":
		return "wallet_score"
	case "tx-decode":
		return "tx_decode"
	default:
		return ""
	}
}

func defaultNetworkForJob(jobType string) string {
	if jobType == legacyTokenScanJobType || jobType == CanonicalInvestigationJobType {
		return "solana-mainnet"
	}
	return "solana-devnet"
}
