package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/defense"
)

// OwnerDefenseDeployment resolves deployed Solana program bytes and records a
// non-authoritative, immutable source/binary verification snapshot.
func (h *Handler) OwnerDefenseDeployment(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, err := defense.ListDeploymentSnapshots(r.Context(), h.DB, r.URL.Query().Get("program_id"), r.URL.Query().Get("network"), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "deployment_snapshot_list_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":                true,
			"deployments":       items,
			"verdict_authority": false,
		})
	case http.MethodPost:
		var input defense.DeploymentResolveInput
		if err := decodeJSON(r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_deployment_request"})
			return
		}
		input.ProgramID = strings.TrimSpace(input.ProgramID)
		input.Network = strings.TrimSpace(input.Network)
		if input.ProgramID == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "program_id_required"})
			return
		}
		if h.SolanaRPC == nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "solana_rpc_unavailable"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 25*time.Second)
		defer cancel()
		snapshot, err := defense.ResolveAndPersistDeployment(ctx, h.DB, h.SolanaRPC, input)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":   "deployment_resolution_failed",
				"details": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"ok":                       true,
			"deployment":               snapshot,
			"read_only_rpc":            true,
			"mainnet_transaction_sent": false,
			"verdict_authority":        false,
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
