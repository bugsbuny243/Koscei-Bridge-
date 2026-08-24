package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"koschei/api/internal/defense"
)

type defenseHarnessExecutionRequest struct {
	Action              string                              `json:"action"`
	PlanRef             string                              `json:"plan_ref"`
	HarnessArtifactRef  string                              `json:"harness_artifact_ref"`
	Engine              string                              `json:"engine"`
	WorkerID            string                              `json:"worker_id"`
	WorkerImageDigest   string                              `json:"worker_image_digest"`
	ConfirmedInvariants []defense.ConfirmedHarnessInvariant `json:"confirmed_invariants"`
	MaxDurationSeconds  int                                 `json:"max_duration_seconds"`
	MaxOutputBytes      int                                 `json:"max_output_bytes"`
}

// OwnerDefenseHarnessExecution creates and reads immutable Phase 12 execution
// profiles. Phase 12A exposes no command execution or worker enqueue action.
func (h *Handler) OwnerDefenseHarnessExecution(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, err := defense.ListHarnessExecutionProfiles(r.Context(), h.DB, r.URL.Query().Get("plan_ref"), r.URL.Query().Get("worker_id"), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "harness_execution_profile_list_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":                       true,
			"profiles":                 items,
			"harness_executed":         false,
			"mainnet_transaction_sent": false,
			"verdict_authority":        false,
		})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !envBool("KOSCHEI_DEFENSE_HARNESS_EXECUTION_GATE_ENABLED", false) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "defense_harness_execution_gate_disabled"})
		return
	}
	var input defenseHarnessExecutionRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_harness_execution_request"})
		return
	}
	if strings.ToLower(strings.TrimSpace(input.Action)) != "assess" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_harness_execution_action"})
		return
	}
	profile, err := defense.CreateHarnessExecutionProfile(r.Context(), h.DB, defense.HarnessExecutionProfileInput{
		PlanRef:             input.PlanRef,
		HarnessArtifactRef:  input.HarnessArtifactRef,
		Engine:              input.Engine,
		WorkerID:            input.WorkerID,
		WorkerImageDigest:   input.WorkerImageDigest,
		ConfirmedInvariants: input.ConfirmedInvariants,
		MaxDurationSeconds:  input.MaxDurationSeconds,
		MaxOutputBytes:      input.MaxOutputBytes,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "harness_execution_profile_rejected", "details": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":                       true,
		"execution_profile":        profile,
		"harness_executed":         false,
		"mainnet_transaction_sent": false,
		"verdict_authority":        false,
	})
}
