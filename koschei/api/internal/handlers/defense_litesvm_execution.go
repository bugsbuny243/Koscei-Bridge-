package handlers

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"

	"koschei/api/internal/defense"
)

type defenseLiteSVMExecutionRequest struct {
	Action             string `json:"action"`
	ProfileRef         string `json:"profile_ref"`
	MaterializationRef string `json:"materialization_ref"`
}

// OwnerDefenseLiteSVMExecution exposes only the Phase 12C control plane. The web
// process can enqueue a fixed action and read immutable attempt evidence; it
// never materializes files or launches a command.
func (h *Handler) OwnerDefenseLiteSVMExecution(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		attemptRef := strings.TrimSpace(r.URL.Query().Get("attempt_ref"))
		if attemptRef != "" {
			attempt, err := defense.LoadLiteSVMExecutionAttempt(r.Context(), h.DB, attemptRef)
			if err != nil {
				writeJSON(w, http.StatusNotFound, map[string]any{"error": "defense_litesvm_attempt_not_found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{
				"ok": true,
				"attempt": attempt,
				"web_executed": false,
				"mainnet_transaction_sent": false,
				"verdict_authority": false,
			})
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, err := defense.ListLiteSVMExecutionAttempts(r.Context(), h.DB,
			r.URL.Query().Get("job_ref"), r.URL.Query().Get("profile_ref"), r.URL.Query().Get("materialization_ref"), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "defense_litesvm_attempt_list_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true,
			"attempts": items,
			"web_executed": false,
			"mainnet_transaction_sent": false,
			"verdict_authority": false,
		})
	case http.MethodPost:
		if !envBool("KOSCHEI_DEFENSE_HARNESS_EXECUTION_ENABLED", false) ||
			!envBool("KOSCHEI_DEFENSE_LITESVM_EXECUTION_ENABLED", false) ||
			!envBool("KOSCHEI_DEFENSE_WORKER_QUEUE_ENABLED", false) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": "defense_litesvm_execution_gate_disabled",
				"web_executed": false,
				"mainnet_transaction_sent": false,
				"verdict_authority": false,
			})
			return
		}
		var input defenseLiteSVMExecutionRequest
		if err := decodeStrictDefenseLiteSVMRequest(w, r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_defense_litesvm_execution_request", "details": err.Error()})
			return
		}
		if !strings.EqualFold(strings.TrimSpace(input.Action), "enqueue") {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "unsupported_defense_litesvm_execution_action"})
			return
		}
		job, err := defense.EnqueueWorkerJob(r.Context(), h.DB, defense.WorkerJobRequest{
			Action: defense.WorkerActionRunLiteSVMHarness,
			ProfileRef: input.ProfileRef,
			MaterializationRef: input.MaterializationRef,
		})
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "defense_litesvm_execution_rejected", "details": err.Error()})
			return
		}
		writeJSON(w, http.StatusAccepted, map[string]any{
			"ok": true,
			"job": job,
			"execution_service": "railway-defense-worker",
			"web_executed": false,
			"network_access": false,
			"dependency_resolution": false,
			"wallet_material_accessed": false,
			"mainnet_rpc_accessed": false,
			"mainnet_transaction_sent": false,
			"verdict_authority": false,
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func decodeStrictDefenseLiteSVMRequest(w http.ResponseWriter, r *http.Request, dst *defenseLiteSVMExecutionRequest) error {
	r.Body = http.MaxBytesReader(w, r.Body, 64*1024)
	decoder := json.NewDecoder(r.Body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(dst); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("request body must contain exactly one JSON object")
		}
		return err
	}
	dst.Action = strings.TrimSpace(dst.Action)
	dst.ProfileRef = strings.TrimSpace(dst.ProfileRef)
	dst.MaterializationRef = strings.TrimSpace(dst.MaterializationRef)
	if dst.Action == "" || dst.ProfileRef == "" || dst.MaterializationRef == "" {
		return errors.New("action, profile_ref and materialization_ref are required")
	}
	return nil
}
