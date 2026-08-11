package handlers

import (
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const publicCaseRegistrySchemaVersion = "koschei-public-case-registry-v1"

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

type publicDossierCasesV2Load struct {
	Cases                   []publicDossierCaseV2
	TotalPublications       int
	InspectedPublications   int
	InvalidPublications     int
	UninspectedPublications int
}

// PublicDossierCasesV2 is the canonical public case projection. A corrupt or
// missing explicitly-public bundle is isolated from rendering, but it is never
// hidden from registry health. A response is complete only when every public
// publication in scope was inspected and passed immutable-bundle verification.
func (h *Handler) PublicDossierCasesV2(w http.ResponseWriter, r *http.Request) {
	limit := publicDossierLimit(r.URL.Query().Get("limit"), 24, 100)
	loaded, err := h.loadPublicDossierCasesV2(r, limit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "error": "public_cases_unavailable", "cases": []publicDossierCaseV2{},
		})
		return
	}
	complete := loaded.InvalidPublications == 0 && loaded.UninspectedPublications == 0
	registryStatus := "operational"
	switch {
	case loaded.InvalidPublications > 0:
		registryStatus = "degraded"
	case loaded.UninspectedPublications > 0:
		registryStatus = "partial"
	}
	w.Header().Set("Cache-Control", "public, max-age=15, stale-while-revalidate=60")
	w.Header().Set("X-Koschei-Registry-Complete", strconv.FormatBool(complete))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                       true,
		"schema_version":           publicCaseRegistrySchemaVersion,
		"generated_at":             time.Now().UTC(),
		"registry_status":          registryStatus,
		"registry_complete":        complete,
		"total_publications":       loaded.TotalPublications,
		"inspected_publications":   loaded.InspectedPublications,
		"invalid_publications":     loaded.InvalidPublications,
		"uninspected_publications": loaded.UninspectedPublications,
		"count":                    len(loaded.Cases),
		"publication_policy": map[string]any{
			"deterministic_autopublish_supported":      true,
			"owner_publication_decisions_preserved":    true,
			"private_customer_investigations_excluded": true,
			"identity_or_wrongdoing_claim":             false,
			"immutable_source_bundle":                  true,
			"canonical_bundle_hash_reverified":         true,
			"partial_registry_declared":                true,
		},
		"cases": loaded.Cases,
	})
}

func (h *Handler) loadPublicDossierCasesV2(r *http.Request, limit int) (publicDossierCasesV2Load, error) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return publicDossierCasesV2Load{}, sql.ErrConnDone
	}
	rows, err := db.QueryContext(r.Context(), `
		SELECT p.case_ref,p.public_title,p.public_summary,p.featured,p.redaction_profile,p.published_at,
		       e.canonical_bundle,e.bundle_hash,COUNT(*) OVER()
		FROM dossier_publications p
		LEFT JOIN dossier_exports e ON e.case_ref=p.case_ref
		WHERE p.status='public'
		ORDER BY p.featured DESC,p.published_at DESC,p.case_ref
		LIMIT $1`, limit)
	if err != nil {
		return publicDossierCasesV2Load{}, err
	}
	defer rows.Close()
	loaded := publicDossierCasesV2Load{Cases: []publicDossierCaseV2{}}
	for rows.Next() {
		var caseRef, title, summary, profile string
		var featured bool
		var publishedAt sql.NullTime
		var canonical []byte
		var storedHash sql.NullString
		var total int
		if err := rows.Scan(&caseRef, &title, &summary, &featured, &profile, &publishedAt, &canonical, &storedHash, &total); err != nil {
			return publicDossierCasesV2Load{}, err
		}
		if loaded.InspectedPublications == 0 {
			loaded.TotalPublications = total
		} else if loaded.TotalPublications != total {
			return publicDossierCasesV2Load{}, fmt.Errorf("public dossier registry total changed within one result set")
		}
		loaded.InspectedPublications++
		if !publishedAt.Valid || !storedHash.Valid || len(canonical) == 0 {
			loaded.InvalidPublications++
			log.Printf("public dossier withheld from registry: publication/export integrity incomplete case_ref=%s", caseRef)
			continue
		}
		bundle, err := verifyStoredDossierBundle(canonical, caseRef, storedHash.String)
		if err != nil {
			loaded.InvalidPublications++
			log.Printf("public dossier withheld from registry: immutable integrity failure case_ref=%s", caseRef)
			continue
		}
		loaded.Cases = append(loaded.Cases, buildPublicDossierCaseV2(bundle, title, summary, featured, publishedAt.Time, profile))
	}
	if err := rows.Err(); err != nil {
		return publicDossierCasesV2Load{}, err
	}
	if loaded.TotalPublications < loaded.InspectedPublications {
		return publicDossierCasesV2Load{}, fmt.Errorf("public dossier registry count is inconsistent")
	}
	loaded.UninspectedPublications = loaded.TotalPublications - loaded.InspectedPublications
	return loaded, nil
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
