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
// canonical nine-state counts plus publication-ledger provenance. Transition
// UUIDs remain internal; public readers only receive the verified lineage state.
type publicDossierCaseV2 struct {
	publicDossierCase
	WindowOpenRows          int            `json:"window_open_rows"`
	PendingRows             int            `json:"pending_rows"`
	NotInvestigatedRows     int            `json:"not_investigated_rows"`
	NotApplicableRows       int            `json:"not_applicable_rows"`
	UnavailableRows         int            `json:"unavailable_rows"`
	UnknownRows             int            `json:"unknown_rows"`
	OpenRows                int            `json:"open_rows"`
	BlockedRows             int            `json:"blocked_rows"`
	StateCounts             map[string]int `json:"state_counts"`
	PublishedBy             string         `json:"published_by"`
	PublicationLedgerStatus string         `json:"publication_ledger_status"`
	PublicationAction       string         `json:"publication_action,omitempty"`
}

type publicDossierCasesV2Load struct {
	Cases                      []publicDossierCaseV2
	TotalPublications          int
	InspectedPublications      int
	InvalidPublications        int
	UninspectedPublications    int
	LedgerVerifiedPublications int
	LegacyUnlinkedPublications int
	InvalidLedgerPublications  int
}

// PublicDossierCasesV2 is the canonical public case projection. A corrupt or
// missing explicitly-public bundle, or a linked publication whose immutable
// transition event no longer matches current state, is isolated from rendering
// and declared through registry health. Pre-linkage rows remain readable but are
// explicitly marked legacy_unlinked instead of receiving invented provenance.
func (h *Handler) PublicDossierCasesV2(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	limit := publicDossierLimit(r.URL.Query().Get("limit"), 24, 100)
	loaded, err := h.loadPublicDossierCasesV2(r, limit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok": false, "error": "public_cases_unavailable", "cases": []publicDossierCaseV2{},
		})
		return
	}
	complete := loaded.InvalidPublications == 0 && loaded.UninspectedPublications == 0
	ledgerComplete := loaded.InvalidLedgerPublications == 0 && loaded.UninspectedPublications == 0 && loaded.LegacyUnlinkedPublications == 0
	registryStatus := "operational"
	switch {
	case loaded.InvalidPublications > 0:
		registryStatus = "degraded"
	case loaded.UninspectedPublications > 0:
		registryStatus = "partial"
	}
	ledgerStatus := "verified"
	switch {
	case loaded.InvalidLedgerPublications > 0:
		ledgerStatus = "degraded"
	case loaded.UninspectedPublications > 0:
		ledgerStatus = "partial"
	case loaded.LegacyUnlinkedPublications > 0:
		ledgerStatus = "legacy_mixed"
	}
	w.Header().Set("X-Koschei-Registry-Complete", strconv.FormatBool(complete))
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                           true,
		"schema_version":               publicCaseRegistrySchemaVersion,
		"generated_at":                 time.Now().UTC(),
		"registry_status":              registryStatus,
		"registry_complete":            complete,
		"publication_ledger_status":    ledgerStatus,
		"publication_ledger_complete":  ledgerComplete,
		"total_publications":           loaded.TotalPublications,
		"inspected_publications":       loaded.InspectedPublications,
		"invalid_publications":         loaded.InvalidPublications,
		"uninspected_publications":     loaded.UninspectedPublications,
		"ledger_verified_publications": loaded.LedgerVerifiedPublications,
		"legacy_unlinked_publications": loaded.LegacyUnlinkedPublications,
		"invalid_ledger_publications":  loaded.InvalidLedgerPublications,
		"count":                        len(loaded.Cases),
		"publication_policy": map[string]any{
			"deterministic_autopublish_supported":      true,
			"owner_publication_decisions_preserved":    true,
			"private_customer_investigations_excluded": true,
			"identity_or_wrongdoing_claim":             false,
			"immutable_source_bundle":                  true,
			"canonical_bundle_hash_reverified":         true,
			"publication_ledger_readback_verified":     true,
			"legacy_publication_lineage_declared":      true,
			"transition_identifiers_public":            false,
			"partial_registry_declared":                true,
		},
		"cases": loaded.Cases,
	})
}

func (h *Handler) loadPublicDossierCasesV2(r *http.Request, limit int) (publicDossierCasesV2Load, error) {
	// Publication visibility is revocable security state. Read it from the
	// primary database so a lagging read replica cannot extend public exposure
	// after an owner hide/draft transition commits.
	db := h.DB
	if db == nil {
		return publicDossierCasesV2Load{}, sql.ErrConnDone
	}
	rows, err := db.QueryContext(r.Context(), `
		SELECT p.case_ref,p.public_title,p.public_summary,p.featured,p.redaction_profile,p.published_at,p.published_by,
		       p.transition_id::text,
		       e.canonical_bundle,e.bundle_hash,
		       pe.transition_id::text,pe.case_ref,pe.actor,pe.action,
		       pe.publication_state->>'status',pe.publication_state->>'published_by',
		       pe.publication_state->>'public_title',pe.publication_state->>'public_summary',
		       pe.publication_state->>'redaction_profile',pe.publication_state->>'featured',
		       COUNT(*) OVER()
		FROM dossier_publications p
		LEFT JOIN dossier_exports e ON e.case_ref=p.case_ref
		LEFT JOIN dossier_publication_events pe ON pe.transition_id=p.transition_id
		WHERE p.status='public'
		ORDER BY p.featured DESC,p.published_at DESC,p.case_ref
		LIMIT $1`, limit)
	if err != nil {
		return publicDossierCasesV2Load{}, err
	}
	defer rows.Close()
	loaded := publicDossierCasesV2Load{Cases: []publicDossierCaseV2{}}
	for rows.Next() {
		var caseRef, title, summary, profile, publishedBy string
		var featured bool
		var publishedAt sql.NullTime
		var canonical []byte
		var storedHash sql.NullString
		var readback publicationLedgerReadback
		var total int
		if err := rows.Scan(
			&caseRef, &title, &summary, &featured, &profile, &publishedAt, &publishedBy,
			&readback.TransitionID,
			&canonical, &storedHash,
			&readback.EventTransitionID, &readback.EventCaseRef, &readback.EventActor, &readback.EventAction,
			&readback.EventStatus, &readback.EventPublishedBy, &readback.EventTitle, &readback.EventSummary,
			&readback.EventProfile, &readback.EventFeatured,
			&total,
		); err != nil {
			return publicDossierCasesV2Load{}, err
		}
		if loaded.InspectedPublications == 0 {
			loaded.TotalPublications = total
		} else if loaded.TotalPublications != total {
			return publicDossierCasesV2Load{}, fmt.Errorf("public dossier registry total changed within one result set")
		}
		loaded.InspectedPublications++

		ledgerState, publicationAction, err := verifyPublicationLedgerReadback(
			caseRef, "public", title, summary, profile, publishedBy, featured, readback,
		)
		if err != nil {
			loaded.InvalidPublications++
			loaded.InvalidLedgerPublications++
			log.Printf("public dossier withheld from registry: publication ledger readback failure case_ref=%s", caseRef)
			continue
		}
		switch ledgerState {
		case publicationLedgerVerified:
			loaded.LedgerVerifiedPublications++
		case publicationLedgerLegacyUnlinked:
			loaded.LegacyUnlinkedPublications++
		default:
			loaded.InvalidPublications++
			loaded.InvalidLedgerPublications++
			log.Printf("public dossier withheld from registry: unknown publication ledger state case_ref=%s", caseRef)
			continue
		}

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
		loaded.Cases = append(loaded.Cases, buildPublicDossierCaseV2(
			bundle, title, summary, featured, publishedAt.Time, profile, publishedBy, ledgerState, publicationAction,
		))
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

func buildPublicDossierCaseV2(
	bundle dossierBundle,
	title, summary string,
	featured bool,
	publishedAt time.Time,
	profile, publishedBy, ledgerState, publicationAction string,
) publicDossierCaseV2 {
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
		publicDossierCase:       base,
		WindowOpenRows:          counts[signalStateWindowOpen],
		PendingRows:             counts[signalStatePending],
		NotInvestigatedRows:     counts[signalStateNotInvestigated],
		NotApplicableRows:       counts[signalStateNotApplicable],
		UnavailableRows:         counts[signalStateUnavailable],
		UnknownRows:             counts[signalStateUnknown],
		OpenRows:                open,
		BlockedRows:             blocked,
		StateCounts:             counts,
		PublishedBy:             publishedBy,
		PublicationLedgerStatus: ledgerState,
		PublicationAction:       publicationAction,
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
