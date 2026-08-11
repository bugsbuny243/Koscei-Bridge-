package handlers

import (
	"encoding/json"
	"net/http"
	"time"
)

type customerInvestigationHistoryItem struct {
	ID              string         `json:"id"`
	JobType         string         `json:"job_type"`
	Status          string         `json:"status"`
	Network         string         `json:"network,omitempty"`
	Target          string         `json:"target,omitempty"`
	Progress        int            `json:"progress"`
	Attempts        int            `json:"attempts"`
	QueuedAt        time.Time      `json:"queued_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	ErrorCode       string         `json:"error_code,omitempty"`
	ErrorMessage    string         `json:"error_message,omitempty"`
	ResultAvailable bool           `json:"result_available"`
	Result          map[string]any `json:"result,omitempty"`
}

// CustomerInvestigationHistory lists durable canonical investigation jobs owned
// by the authenticated account. Reading history requires Basic KOSCH access but
// does not consume a new scan unit; new scans remain metered at creation.
func (h *Handler) CustomerInvestigationHistory(w http.ResponseWriter, r *http.Request) {
	h.RequireTokenTier("basic", h.customerInvestigationHistoryRead)(w, r)
}

func (h *Handler) customerInvestigationHistoryRead(w http.ResponseWriter, r *http.Request) {
	if h.JobStore == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"error": "job service unavailable"})
		return
	}
	claims, ok := userFromContext(r.Context())
	if !ok {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}

	jobsList, err := h.JobStore.ListByUser(r.Context(), claims.Sub, CanonicalInvestigationJobType, 100)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "investigation history read failed"})
		return
	}

	items := make([]customerInvestigationHistoryItem, 0, len(jobsList))
	for _, job := range jobsList {
		item := customerInvestigationHistoryItem{
			ID: job.ID, JobType: job.Type, Status: job.Status,
			Network: job.Network, Target: job.Target, Progress: job.Progress, Attempts: job.Attempts,
			QueuedAt: job.QueuedAt, UpdatedAt: job.UpdatedAt,
			ErrorCode: job.ErrorCode, ErrorMessage: job.ErrorMessage,
		}
		if len(job.ResultPayload) > 0 && string(job.ResultPayload) != "null" {
			var result map[string]any
			if json.Unmarshal(job.ResultPayload, &result) == nil && result != nil {
				item.ResultAvailable = true
				item.Result = result
			}
		}
		items = append(items, item)
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "schema_version": "koschei-customer-investigation-history-v1",
		"source": "web3_jobs", "job_type": CanonicalInvestigationJobType,
		"history": items, "count": len(items),
	})
}
