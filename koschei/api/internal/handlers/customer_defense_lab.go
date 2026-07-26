package handlers

import (
	"database/sql"
	"net/http"
	"strconv"
	"strings"

	"koschei/api/internal/defense"
)

type customerDefenseLabRequest struct {
	Action      string `json:"action"`
	ArtifactRef string `json:"artifact_ref"`
}

func customerDefenseSubject(r *http.Request) string {
	subject := dossierRequester(r)
	if subject == "owner" && !dossierOwnerCredentialPresent(r) {
		return ""
	}
	return strings.TrimSpace(subject)
}

// CustomerDefenseArtifacts stores and lists only artifacts subscribed to the
// authenticated user/API principal. Source content is never returned by list.
func (h *Handler) CustomerDefenseArtifacts(w http.ResponseWriter, r *http.Request) {
	subject := customerDefenseSubject(r)
	if subject == "" {
		writeAPIError(w, http.StatusUnauthorized, APICodeUnauthorized, "Authenticated user or API key is required")
		return
	}
	switch r.Method {
	case http.MethodGet:
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, err := defense.ListCustomerArtifacts(r.Context(), h.DB, subject, r.URL.Query().Get("program_id"), r.URL.Query().Get("network"), limit)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "customer_artifact_list_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok": true, "artifacts": items, "subject": subject,
			"supported_types": []string{"source_bundle", "source_manifest", "sbpf_manifest", "anchor_idl"},
			"private_by_default": true,
		})
	case http.MethodPost:
		var input defense.ArtifactInput
		if err := decodeJSON(r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_customer_artifact"})
			return
		}
		item, err := defense.StoreCustomerArtifact(r.Context(), h.DB, input, subject)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "customer_artifact_rejected", "details": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"ok": true, "artifact": item, "private_by_default": true,
			"next": map[string]any{"method": "POST", "path": "/api/v1/defense/lab", "action": "analyze", "artifact_ref": item.ArtifactRef},
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// CustomerDefenseLab runs deterministic static analysis over an artifact owned
// by the authenticated principal. Execution, deployment and transaction sending
// are deliberately outside this customer endpoint.
func (h *Handler) CustomerDefenseLab(w http.ResponseWriter, r *http.Request) {
	subject := customerDefenseSubject(r)
	if subject == "" {
		writeAPIError(w, http.StatusUnauthorized, APICodeUnauthorized, "Authenticated user or API key is required")
		return
	}
	if r.Method == http.MethodGet {
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, err := defense.ListCustomerLabRuns(r.Context(), h.DB, subject, limit)
		if err != nil {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "customer_lab_run_list_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"ok": true, "runs": items, "static_only": true, "verdict_authority": false})
		return
	}
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	var input customerDefenseLabRequest
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "invalid_customer_lab_request"})
		return
	}
	if strings.ToLower(strings.TrimSpace(input.Action)) != "analyze" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "unsupported_customer_lab_action"})
		return
	}
	result, err := defense.AnalyzeCustomerArtifact(r.Context(), h.DB, input.ArtifactRef, subject)
	if err != nil {
		status := http.StatusBadRequest
		if err == sql.ErrNoRows {
			status = http.StatusNotFound
		}
		writeJSON(w, status, map[string]any{"ok": false, "error": "customer_lab_analysis_failed", "details": err.Error()})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true, "analysis": result,
		"boundaries": []string{
			"Statik bulgu, sömürülebilirlik veya zincir üstü etki kanıtı değildir.",
			"Bu endpoint komut çalıştırmaz, program dağıtmaz, işlem imzalamaz ve mainnet işlemi göndermez.",
			"Kaynak artifact'ı private kalır; public yayın için ayrı ve açık bir görünürlük işlemi gerekir.",
		},
	})
}
