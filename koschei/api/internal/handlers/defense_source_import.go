package handlers

import (
	"context"
	"net/http"
	"strconv"
	"strings"
	"time"

	"koschei/api/internal/defense"
)

// OwnerDefenseSourceImport imports a bounded public GitHub repository snapshot
// pinned to one exact commit. It is disabled by default and never runs source code.
func (h *Handler) OwnerDefenseSourceImport(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
		items, err := defense.ListSourceImports(r.Context(), h.DB, r.URL.Query().Get("program_id"), r.URL.Query().Get("network"), limit)
		if err != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]any{"error": "source_import_list_failed"})
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"ok":                true,
			"imports":           items,
			"verdict_authority": false,
		})
	case http.MethodPost:
		if !envBool("KOSCHEI_DEFENSE_SOURCE_IMPORT_ENABLED", false) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": "source_import_disabled"})
			return
		}
		var input defense.SourceImportInput
		if err := decodeJSON(r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "invalid_source_import_request"})
			return
		}
		input.ProgramID = strings.TrimSpace(input.ProgramID)
		input.Network = strings.TrimSpace(input.Network)
		input.RepositoryURL = strings.TrimSpace(input.RepositoryURL)
		input.CommitSHA = strings.TrimSpace(input.CommitSHA)
		if input.ProgramID == "" || input.RepositoryURL == "" || input.CommitSHA == "" {
			writeJSON(w, http.StatusBadRequest, map[string]any{"error": "source_import_identity_required"})
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
		defer cancel()
		record, err := defense.ImportSourceRepository(ctx, h.DB, defense.NewSourceImportHTTPClient(), input)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]any{
				"error":   "source_import_failed",
				"details": err.Error(),
			})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{
			"ok":                 true,
			"source_import":      record,
			"source_executed":    false,
			"production_changed": false,
			"verdict_authority":  false,
		})
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}
