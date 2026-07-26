package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

// DossierPublicationAccess accepts a registered user, an API key or an owner
// session. Visibility is controlled by the principal that created the dossier;
// owner access remains a moderation path, not the product's only publisher.
func (h *Handler) DossierPublicationAccess(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if dossierOwnerCredentialPresent(r) {
			if !h.OwnerAuth(w, r) {
				return
			}
			next(w, r)
			return
		}
		apiKey := strings.TrimSpace(r.Header.Get("X-API-Key"))
		bearer := bearerToken(r.Header.Get("Authorization"))
		if apiKey != "" || strings.HasPrefix(bearer, "kch_live_") {
			h.APIKeyAuth(next)(w, r)
			return
		}
		RequireAuth(next)(w, r)
	}
}

// CustomerDossierPublication lets the user or API account that created an
// immutable dossier publish, hide or return it to draft. Featuring remains a
// moderation action on the existing owner route.
func (h *Handler) CustomerDossierPublication(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DB == nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Dossier publication database is unavailable")
		return
	}
	requester := dossierRequester(r)
	if requester == "owner" && !dossierOwnerCredentialPresent(r) {
		writeAPIError(w, http.StatusUnauthorized, APICodeUnauthorized, "Authenticated publisher is required")
		return
	}

	var input dossierPublicationRequest
	if err := decodeJSON(r, &input); err != nil {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Invalid publication request")
		return
	}
	input.CaseRef = strings.TrimSpace(input.CaseRef)
	input.Status = strings.ToLower(strings.TrimSpace(input.Status))
	input.PublicTitle = boundedPublicDossierText(input.PublicTitle, 160)
	input.PublicSummary = boundedPublicDossierText(input.PublicSummary, 600)
	input.RedactionProfile = strings.TrimSpace(input.RedactionProfile)
	if input.RedactionProfile == "" {
		input.RedactionProfile = publicDossierRedactionProfile
	}
	if !publicDossierCaseRefPattern.MatchString(input.CaseRef) {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "A valid immutable case_ref is required")
		return
	}
	if input.Status != "public" && input.Status != "hidden" && input.Status != "draft" {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "status must be public, hidden or draft")
		return
	}
	if input.RedactionProfile != publicDossierRedactionProfile {
		writeAPIError(w, http.StatusBadRequest, APICodeInvalidInput, "Unsupported public redaction profile")
		return
	}
	if input.Featured {
		writeAPIError(w, http.StatusForbidden, APICodeForbidden, "Featuring is a moderation action")
		return
	}

	var canonical []byte
	var requestedBy string
	if err := h.DB.QueryRowContext(r.Context(), `
		SELECT canonical_bundle,requested_by FROM dossier_exports WHERE case_ref=$1`, input.CaseRef).
		Scan(&canonical, &requestedBy); err != nil {
		if err == sql.ErrNoRows {
			writeAPIError(w, http.StatusNotFound, APICodeNotFound, "Immutable dossier was not found")
			return
		}
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Immutable dossier could not be loaded")
		return
	}
	if requester != "owner" && strings.TrimSpace(requestedBy) != requester {
		writeAPIError(w, http.StatusForbidden, APICodeForbidden, "Only the dossier creator can change public visibility")
		return
	}

	var bundle dossierBundle
	if json.Unmarshal(canonical, &bundle) != nil || bundle.CaseRef != input.CaseRef || bundle.BundleHash == "" {
		writeAPIError(w, http.StatusConflict, APICodeConflict, "Immutable dossier bundle is invalid")
		return
	}
	if input.PublicTitle == "" {
		input.PublicTitle = defaultPublicDossierTitle(bundle)
	}
	if input.PublicSummary == "" {
		input.PublicSummary = defaultPublicDossierSummary(bundle)
	}

	tx, err := h.DB.BeginTx(r.Context(), nil)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication transaction could not start")
		return
	}
	defer tx.Rollback()

	previousStatus, previousFeatured := "", false
	previousExists := true
	if err := tx.QueryRowContext(r.Context(), `SELECT status,featured FROM dossier_publications WHERE case_ref=$1`, input.CaseRef).
		Scan(&previousStatus, &previousFeatured); err != nil {
		if err == sql.ErrNoRows {
			previousExists = false
		} else {
			writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication state could not be read")
			return
		}
	}
	_, err = tx.ExecContext(r.Context(), `
		INSERT INTO dossier_publications
			(case_ref,status,public_title,public_summary,featured,redaction_profile,published_at,published_by,created_at,updated_at)
		VALUES
			($1,$2,$3,$4,false,$5,CASE WHEN $2='public' THEN now() ELSE NULL END,$6,now(),now())
		ON CONFLICT (case_ref) DO UPDATE SET
			status=EXCLUDED.status,
			public_title=EXCLUDED.public_title,
			public_summary=EXCLUDED.public_summary,
			featured=CASE WHEN EXCLUDED.status='public' THEN dossier_publications.featured ELSE false END,
			redaction_profile=EXCLUDED.redaction_profile,
			published_at=CASE WHEN EXCLUDED.status='public' THEN COALESCE(dossier_publications.published_at,now()) ELSE dossier_publications.published_at END,
			published_by=EXCLUDED.published_by,
			updated_at=now()`,
		input.CaseRef, input.Status, input.PublicTitle, input.PublicSummary, input.RedactionProfile, requester)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication state could not be saved")
		return
	}
	action := publicDossierPublicationAction(previousExists, previousStatus, previousFeatured, input.Status, false)
	stateJSON, _ := json.Marshal(map[string]any{
		"status": input.Status, "featured": false,
		"public_title": input.PublicTitle, "redaction_profile": input.RedactionProfile,
	})
	if _, err := tx.ExecContext(r.Context(), `
		INSERT INTO dossier_publication_events (case_ref,action,actor,publication_state)
		VALUES ($1,$2,$3,$4::jsonb)`, input.CaseRef, action, requester, string(stateJSON)); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication audit event could not be saved")
		return
	}
	if err := tx.Commit(); err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Publication transaction could not be committed")
		return
	}

	publishedAt := time.Time{}
	if input.Status == "public" {
		_ = h.DB.QueryRowContext(r.Context(), `SELECT published_at FROM dossier_publications WHERE case_ref=$1`, input.CaseRef).Scan(&publishedAt)
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                          true,
		"status":                      input.Status,
		"action":                      action,
		"publisher":                   requester,
		"case":                        buildPublicDossierCase(bundle, input.PublicTitle, input.PublicSummary, false, publishedAt, input.RedactionProfile),
		"immutable_dossier_unchanged": true,
	})
}
