package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"time"
)

// PublicSecurityCases lists the latest public evidence case for each target.
// Publication is controlled by the dossier creator (user, API account or owner)
// while owner privileges are limited to moderation and featuring.
func (h *Handler) PublicSecurityCases(w http.ResponseWriter, r *http.Request) {
	limit := publicDossierLimit(r.URL.Query().Get("limit"), 24, 100)
	cases, err := h.loadCurrentPublicCases(r.Context(), limit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "error": "public_cases_unavailable", "cases": []publicDossierCase{},
		})
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=15, stale-while-revalidate=60")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"generated_at": time.Now().UTC(),
		"count":        len(cases),
		"publication_policy": map[string]any{
			"creator_controls_visibility":           true,
			"owner_is_moderator_not_sole_publisher": true,
			"private_scans_are_private_by_default":  true,
			"identity_or_wrongdoing_claim":          false,
			"immutable_source_bundle":               true,
		},
		"cases": cases,
	})
}

func (h *Handler) loadCurrentPublicCases(ctx context.Context, limit int) ([]publicDossierCase, error) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return nil, sql.ErrConnDone
	}
	if limit <= 0 || limit > 100 {
		limit = 24
	}
	rows, err := db.QueryContext(ctx, `
		WITH ranked AS (
			SELECT p.case_ref,p.public_title,p.public_summary,p.featured,p.redaction_profile,p.published_at,
			       e.canonical_bundle,
			       row_number() OVER (
				   PARTITION BY
				     COALESCE(NULLIF(e.bundle_json->'target'->>'kind',''),'unknown'),
				     COALESCE(NULLIF(e.bundle_json->'target'->>'id',''),NULLIF(e.bundle_json->'target'->>'address',''),NULLIF(e.bundle_json->'target'->>'mint',''),p.case_ref)
				   ORDER BY (e.bundle_json->>'produced_at')::timestamptz DESC,p.published_at DESC,p.case_ref DESC
			       ) AS target_rank
			FROM dossier_publications p
			JOIN dossier_exports e ON e.case_ref=p.case_ref
			WHERE p.status='public'
		)
		SELECT case_ref,public_title,public_summary,featured,redaction_profile,published_at,canonical_bundle
		FROM ranked
		WHERE target_rank=1
		ORDER BY featured DESC,published_at DESC,case_ref
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []publicDossierCase{}
	for rows.Next() {
		var caseRef, title, summary, profile string
		var featured bool
		var publishedAt time.Time
		var canonical []byte
		if err := rows.Scan(&caseRef, &title, &summary, &featured, &profile, &publishedAt, &canonical); err != nil {
			return nil, err
		}
		var bundle dossierBundle
		if json.Unmarshal(canonical, &bundle) != nil || bundle.CaseRef != caseRef || bundle.BundleHash == "" {
			return nil, sql.ErrNoRows
		}
		item := buildPublicDossierCase(bundle, title, summary, featured, publishedAt, profile)
		item.VerdictGrade = publicCaseEffectiveGrade(buildPublicCasePageData(bundle, title, summary, featured, publishedAt))
		if item.VerdictGrade == "WITHHOLD" {
			item.VerdictStatus = "withhold"
		}
		out = append(out, item)
	}
	return out, rows.Err()
}
