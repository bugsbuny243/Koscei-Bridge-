package handlers

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

func (h *Handler) PublicContractFindings(w http.ResponseWriter, r *http.Request) {
	limit := publicDossierLimit(r.URL.Query().Get("limit"), 24, 100)
	items, err := h.loadPublicContractFindings(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "error": "public_contract_findings_unavailable", "findings": []publicContractFinding{},
		})
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=15, stale-while-revalidate=60")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"generated_at": time.Now().UTC(),
		"count": len(items),
		"findings": items,
		"publication_policy": map[string]any{
			"explicit_owner_publish_required": true,
			"minimum_severity": "high",
			"private_source_location_redacted": true,
			"exploit_or_wrongdoing_claim": false,
			"verdict_authority": false,
		},
	})
}

func (h *Handler) PublicContractFindingItem(w http.ResponseWriter, r *http.Request) {
	ref := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/public/contract-findings/"), "/")
	item, err := h.loadPublicContractFindingByRef(r.Context(), ref)
	if errors.Is(err, sql.ErrNoRows) {
		writeJSON(w, http.StatusNotFound, map[string]any{"ok": false, "error": "contract_finding_not_found"})
		return
	}
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "contract_finding_unavailable"})
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=30, stale-while-revalidate=120")
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "finding": item})
}

func (h *Handler) OwnerDefenseFindingPublication(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DB == nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Finding publication database is unavailable")
		return
	}
	var input contractFindingPublicationRequest
	if err := decodeJSON(r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Invalid finding publication request")
		return
	}
	input.FindingRef = strings.TrimSpace(input.FindingRef)
	input.Status = strings.ToLower(strings.TrimSpace(input.Status))
	input.PublicTitle = boundedPublicDossierText(input.PublicTitle, 180)
	input.PublicSummary = boundedPublicDossierText(input.PublicSummary, 1200)
	input.RedactionProfile = strings.TrimSpace(input.RedactionProfile)
	if input.RedactionProfile == "" {
		input.RedactionProfile = publicContractFindingRedactionProfile
	}
	if !publicContractFindingRefPattern.MatchString(input.FindingRef) {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "A valid immutable finding_ref is required")
		return
	}
	if input.Status != "public" && input.Status != "hidden" && input.Status != "draft" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "status must be public, hidden or draft")
		return
	}
	if input.RedactionProfile != publicContractFindingRedactionProfile {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Unsupported public finding redaction profile")
		return
	}

	eligibility, err := loadContractFindingEligibility(r.Context(), h.DB, input.FindingRef)
	if errors.Is(err, sql.ErrNoRows) {
		writeAPIError(w, http.StatusNotFound, APICodeNotFound, "Immutable finding was not found")
		return
	}
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Finding eligibility could not be loaded")
		return
	}
	if input.Status == "public" && !publicContractFindingEligible(
		eligibility.Severity, eligibility.Confidence, eligibility.Lifecycle, eligibility.ArtifactTrust,
	) {
		writeAPIError(w, http.StatusConflict, APICodeConflict, "Finding does not satisfy the public evidence policy")
		return
	}
	if input.PublicTitle == "" {
		input.PublicTitle = defaultPublicContractFindingTitle(eligibility.RuleID, eligibility.FindingTitle)
	}
	if input.PublicSummary == "" {
		input.PublicSummary = defaultPublicContractFindingSummary(eligibility.Severity, eligibility.Confidence, eligibility.Lifecycle)
	}

	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Finding publication transaction could not start")
		return
	}
	defer tx.Rollback()
	previousStatus := ""
	previousExists := true
	if err := tx.QueryRowContext(r.Context(), `SELECT status FROM defense_finding_publications WHERE finding_ref=$1`, input.FindingRef).Scan(&previousStatus); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			previousExists = false
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Finding publication state could not be read")
			return
		}
	}
	_, err = tx.ExecContext(r.Context(), `
		INSERT INTO defense_finding_publications
			(finding_ref,status,public_title,public_summary,redaction_profile,published_at,published_by,created_at,updated_at)
		VALUES
			($1,$2,$3,$4,$5,CASE WHEN $2='public' THEN now() ELSE NULL END,
			 CASE WHEN $2='public' THEN 'owner' ELSE NULL END,now(),now())
		ON CONFLICT (finding_ref) DO UPDATE SET
			status=EXCLUDED.status,
			public_title=EXCLUDED.public_title,
			public_summary=EXCLUDED.public_summary,
			redaction_profile=EXCLUDED.redaction_profile,
			published_at=CASE WHEN EXCLUDED.status='public' THEN COALESCE(defense_finding_publications.published_at,now()) ELSE defense_finding_publications.published_at END,
			published_by=CASE WHEN EXCLUDED.status='public' THEN 'owner' ELSE defense_finding_publications.published_by END,
			updated_at=now()`,
		input.FindingRef, input.Status, input.PublicTitle, input.PublicSummary, input.RedactionProfile)
	if err != nil {
		writeAPIError(w, http.StatusConflict, APICodeConflict, "Finding publication state was rejected")
		return
	}
	action := publicContractFindingPublicationAction(previousExists, previousStatus, input.Status)
	stateJSON, _ := json.Marshal(map[string]any{
		"status": input.Status,
		"public_title": input.PublicTitle,
		"redaction_profile": input.RedactionProfile,
	})
	if _, err := tx.ExecContext(r.Context(), `
		INSERT INTO defense_finding_publication_events (finding_ref,action,actor,publication_state)
		VALUES ($1,$2,'owner',$3::jsonb)`, input.FindingRef, action, string(stateJSON)); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Finding publication audit event could not be saved")
		return
	}
	if err := tx.Commit(); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Finding publication transaction could not be committed")
		return
	}

	response := map[string]any{
		"ok": true,
		"status": input.Status,
		"action": action,
		"finding_ref": input.FindingRef,
		"redaction_profile": input.RedactionProfile,
		"immutable_finding_unchanged": true,
	}
	if input.Status == "public" {
		if item, loadErr := h.loadPublicContractFindingByRef(r.Context(), input.FindingRef); loadErr == nil {
			response["finding"] = item
		}
	}
	writeJSON(w, http.StatusOK, response)
}
