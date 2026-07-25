package handlers

import (
	"net/http"
	"strconv"
	"strings"

	"koschei/api/internal/defense"
)

// OwnerDefenseWorkerJobs creates and inspects jobs consumed by a separate
// Railway Defense Worker service. The web process never executes the job.
func (h *Handler) OwnerDefenseWorkerJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		jobRef := strings.TrimSpace(r.URL.Query().Get("job_ref"))
		if jobRef != "" {
			job, err := defense.GetWorkerJob(r.Context(), h.DB, jobRef)
			if err != nil {
				writeJSON(w, http.StatusNotFound, map[string]any{"error": "defense_worker_job_not_found"})
				return
			}
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "job": job, "web_executed": false})
			return
		}
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, err := defense.ListWorkerJobs(r.Context(), h.DB, r.URL.Query().Get("status"), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "defense_worker_job_list_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "jobs": items, "web_executed": false})
	case http.MethodPost:
		if !envBool("KOSCHEI_DEFENSE_WORKER_QUEUE_ENABLED", false) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "defense_worker_queue_disabled"})
			return
		}
		var request defense.WorkerJobRequest
		if err := decodeJSON(r, &request); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_defense_worker_job"})
			return
		}
		if strings.EqualFold(strings.TrimSpace(request.Action), defense.WorkerActionRunLiteSVMHarness) &&
			(!envBool("KOSCHEI_DEFENSE_HARNESS_EXECUTION_ENABLED", false) || !envBool("KOSCHEI_DEFENSE_LITESVM_EXECUTION_ENABLED", false)) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"error": "defense_litesvm_execution_gate_disabled",
				"web_executed": false,
				"mainnet_transaction_sent": false,
				"verdict_authority": false,
			})
			return
		}
		job, err := defense.EnqueueWorkerJob(r.Context(), h.DB, request)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "defense_worker_job_rejected", "details": err.Error()})
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
