package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"koschei/api/internal/defense"
)

type defenseHarnessMaterializationRequest struct {
	Action     string `json:"action"`
	ProfileRef string `json:"profile_ref"`
}

// OwnerDefenseHarnessMaterialization creates and lists deterministic immutable
// harness materializations. It never resolves dependencies or executes source.
func (h *Handler) OwnerDefenseHarnessMaterialization(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, err := defense.ListHarnessMaterializations(r.Context(), h.DB, r.URL.Query().Get("profile_ref"), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "harness_materialization_list_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":                       true,
			"materializations":         items,
			"dependency_resolution":    false,
			"source_executed":          false,
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
	if !envBool("KOSCHEI_DEFENSE_HARNESS_MATERIALIZATION_ENABLED", false) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "defense_harness_materialization_disabled"})
		return
	}
	var input defenseHarnessMaterializationRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_harness_materialization_request"})
		return
	}
	if strings.ToLower(strings.TrimSpace(input.Action)) != "materialize" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_harness_materialization_action"})
		return
	}
	item, err := defense.CreateHarnessMaterialization(r.Context(), h.DB, defense.HarnessMaterializationInput{ProfileRef: input.ProfileRef})
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"error": "harness_materialization_rejected", "details": err.Error()})
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{
		"ok":                       true,
		"materialization":          item,
		"dependency_resolution":    false,
		"source_executed":          false,
		"harness_executed":         false,
		"mainnet_transaction_sent": false,
		"verdict_authority":        false,
	})
}
