package handlers

import (
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"
	"time"
)

// publicDossierCaseV2 keeps the existing discovery contract and adds the
// canonical nine-state counts. Outer JSON fields intentionally replace the old
// catch-all unknown count from the embedded compatibility projection.
type publicDossierCaseV2 struct {
	publicDossierCase
	WindowOpenRows      int            `json:"window_open_rows"`
	PendingRows         int            `json:"pending_rows"`
	NotInvestigatedRows int            `json:"not_investigated_rows"`
	NotApplicableRows   int            `json:"not_applicable_rows"`
	UnavailableRows     int            `json:"unavailable_rows"`
	UnknownRows         int            `json:"unknown_rows"`
	OpenRows            int            `json:"open_rows"`
	BlockedRows         int            `json:"blocked_rows"`
	StateCounts         map[string]int `json:"state_counts"`
}

// PublicDossierCasesV2 is the canonical public case projection. A corrupt
// bundle is isolated and logged instead of blanking the complete showcase.
func (h *Handler) PublicDossierCasesV2(w http.ResponseWriter, r *http.Request) {
	limit := publicDossierLimit(r.URL.Query().Get("limit"), 24, 100)
	cases, err := h.loadPublicDossierCasesV2(r, limit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "error": "public_cases_unavailable", "cases": []publicDossierCaseV2{},
		})
		return
	}
	w.Header().Set("Cache-Control", "public, max-age=15, stale-while-revalidate=60")
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":           true,
		"generated_at": time.Now().UTC(),
		"count":        len(cases),
		"publication_policy": map[string]any{
			"deterministic_autopublish_supported":      true,
			"owner_publication_decisions_preserved":    true,
			"private_customer_investigations_excluded": true,
			"identity_or_wrongdoing_claim":             false,
			"immutable_source_bundle":                  true,
		},
		"cases": cases,
	})
}

func (h *Handler) loadPublicDossierCasesV2(r *http.Request, limit int) ([]publicDossierCaseV2, error) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return nil, sql.ErrConnDone
	}
	rows, err := db.QueryContext(r.Context(), `
		SELECT p.case_ref,p.public_title,p.public_summary,p.featured,p.redaction_profile,p.published_at,e.canonical_bundle
		FROM dossier_publications p
		JOIN dossier_exports e ON e.case_ref=p.case_ref
		WHERE p.status='public'
		ORDER BY p.featured DESC,p.published_at DESC,p.case_ref
		LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []publicDossierCaseV2{}
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
			log.Printf("public dossier skipped: invalid immutable bundle case_ref=%s", caseRef)
			continue
		}
		out = append(out, buildPublicDossierCaseV2(bundle, title, summary, featured, publishedAt, profile))
	}
	return out, rows.Err()
}

func buildPublicDossierCaseV2(bundle dossierBundle, title, summary string, featured bool, publishedAt time.Time, profile string) publicDossierCaseV2 {
	base := buildPublicDossierCase(bundle, title, summary, featured, publishedAt, profile)
	counts := map[string]int{
		signalStateVerified: 0, signalStateObserved: 0, signalStateInferred: 0,
		signalStateNotApplicable: 0, signalStateWindowOpen: 0, signalStatePending: 0,
		signalStateNotInvestigated: 0, signalStateUnavailable: 0, signalStateUnknown: 0,
	}
	rows := dossierSlice(dossierMap(bundle.VerdictCard)["signal_rows"])
	for _, raw := range rows {
		state := normalizeSignalState(dossierString(dossierMap(raw)["state"]))
		counts[state]++
	}
	open := counts[signalStateWindowOpen] + counts[signalStatePending] + counts[signalStateNotInvestigated]
	blocked := counts[signalStateUnavailable] + counts[signalStateUnknown]
	base.VerifiedRows = counts[signalStateVerified]
	base.ObservedRows = counts[signalStateObserved]
	base.InferredRows = counts[signalStateInferred]
	return publicDossierCaseV2{
		publicDossierCase:   base,
		WindowOpenRows:      counts[signalStateWindowOpen],
		PendingRows:         counts[signalStatePending],
		NotInvestigatedRows: counts[signalStateNotInvestigated],
		NotApplicableRows:   counts[signalStateNotApplicable],
		UnavailableRows:     counts[signalStateUnavailable],
		UnknownRows:         counts[signalStateUnknown],
		OpenRows:            open,
		BlockedRows:         blocked,
		StateCounts:         counts,
	}
}

func publicCaseStateCounts(rows []publicCaseSignalView) map[string]int {
	counts := map[string]int{}
	for _, row := range rows {
		state := normalizeSignalState(strings.TrimSpace(row.State))
		counts[state]++
	}
	return counts
}
