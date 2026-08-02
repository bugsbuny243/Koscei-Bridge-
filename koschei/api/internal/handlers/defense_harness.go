package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"koschei/api/internal/defense"
)

type defenseHarnessRequest struct {
	Action            string `json:"action"`
	IDLArtifactRef    string `json:"idl_artifact_ref"`
	SourceArtifactRef string `json:"source_artifact_ref"`
}

// OwnerDefenseHarness creates deterministic Anchor IDL harness plans and reads
// Railway worker toolchain attestations. It never executes source in the web process.
func (h *Handler) OwnerDefenseHarness(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		if strings.EqualFold(strings.TrimSpace(r.URL.Query().Get("view")), "toolchains") {
			items, err := defense.ListPinnedToolchainAttestations(r.Context(), h.DB, r.URL.Query().Get("worker_id"), limit)
			if err != nil {
				writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "toolchain_attestation_list_failed"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"ok":                              true,
				"toolchains":                      items,
				"execution_requires_pinned_tools": true,
				"verdict_authority":               false,
			})
			return
		}
		items, err := defense.ListHarnessPlans(r.Context(), h.DB, r.URL.Query().Get("program_id"), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "harness_plan_list_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "plans": items, "web_executed": false, "verdict_authority": false})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !envBool("KOSCHEI_DEFENSE_HARNESS_PLANNER_ENABLED", false) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "defense_harness_planner_disabled"})
		return
	}
	var input defenseHarnessRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_harness_request"})
		return
	}
	if strings.ToLower(strings.TrimSpace(input.Action)) != "generate" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_harness_action"})
		return
	}
	plan, err := defense.GenerateHarnessPlan(r.Context(), h.DB, defense.HarnessPlanInput{
		IDLArtifactRef:    input.IDLArtifactRef,
		SourceArtifactRef: input.SourceArtifactRef,
	})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "harness_plan_rejected", "details": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":                       true,
		"harness_plan":             plan,
		"execution_ready":          false,
		"manual_guidance_required": true,
		"web_executed":             false,
		"verdict_authority":        false,
	})
}
