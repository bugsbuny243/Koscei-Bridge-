package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"koschei/api/internal/defense"
)

type defenseReproductionRequest struct {
	Action            string `json:"action"`
	InvariantRef      string `json:"invariant_ref"`
	InvariantVersion  string `json:"invariant_version"`
	FindingRef        string `json:"finding_ref"`
	SourceArtifactRef string `json:"source_artifact_ref"`
	PatchRef          string `json:"patch_ref"`
	Command           string `json:"command"`
	BaselineMarker    string `json:"baseline_marker"`
	PatchedMarker     string `json:"patched_marker"`
	Rationale         string `json:"rationale"`
	BaselineJobRef    string `json:"baseline_job_ref"`
	PatchedJobRef     string `json:"patched_job_ref"`
}

// OwnerDefenseReproduction manages versioned worker-run invariants and paired
// proof finalization. It never executes source in the web process.
func (h *Handler) OwnerDefenseReproduction(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		runs, err := defense.ListReproductionRuns(r.Context(), h.DB, r.URL.Query().Get("finding_ref"), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "reproduction_run_list_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "runs": runs, "verdict_authority": false})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !envBool("KOSCHEI_DEFENSE_REPRODUCTION_ENABLED", false) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "defense_reproduction_disabled"})
		return
	}
	var input defenseReproductionRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_reproduction_request"})
		return
	}
	switch strings.ToLower(strings.TrimSpace(input.Action)) {
	case "create_invariant":
		invariant, err := defense.CreateReproductionInvariant(r.Context(), h.DB, defense.ReproductionInvariantInput{
			FindingRef:        input.FindingRef,
			SourceArtifactRef: input.SourceArtifactRef,
			InvariantVersion:  input.InvariantVersion,
			Command:           input.Command,
			BaselineMarker:    input.BaselineMarker,
			PatchedMarker:     input.PatchedMarker,
			Rationale:         input.Rationale,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "reproduction_invariant_rejected", "details": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"ok": true, "invariant": invariant, "human_approved": true, "verdict_authority": false})
	case "prepare_pair":
		if !envBool("KOSCHEI_DEFENSE_WORKER_QUEUE_ENABLED", false) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "defense_worker_queue_disabled"})
			return
		}
		pair, err := defense.PrepareReproductionPair(r.Context(), h.DB, input.InvariantRef, input.PatchRef)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "reproduction_pair_rejected", "details": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{"ok": true, "pair": pair, "execution_service": "railway-defense-worker", "web_executed": false})
	case "finalize_pair":
		run, err := defense.FinalizeReproductionPair(r.Context(), h.DB, input.InvariantRef, input.PatchRef, input.BaselineJobRef, input.PatchedJobRef)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "reproduction_pair_not_finalized", "details": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"ok":                true,
			"reproduction_run":  run,
			"proof_verified":    run.Status == "verified" && run.ProofRef != "",
			"verdict_authority": false,
		})
	default:
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_reproduction_action"})
	}
}
