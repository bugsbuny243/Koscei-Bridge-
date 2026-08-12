package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"
)

var (
	errPublicExposureNotAuthorized = errors.New("public exposure is not authorized")
	errPublicExposureIntegrity     = errors.New("public exposure dossier integrity failed")
)

type publicExposureRecord struct {
	Bundle            dossierBundle
	Title             string
	Summary           string
	Featured          bool
	PublishedAt       time.Time
	PublishedBy       string
	LedgerStatus      string
	PublicationAction string
}

// loadPublicExposureRecord reads publication authorization, its immutable ledger
// event and the immutable dossier export in one PostgreSQL statement snapshot.
// A linked publication whose state/event pair no longer verifies is treated as
// not publicly authorized. Pre-linkage rows remain readable as legacy_unlinked;
// the system never manufactures a historical transition proof for them.
func loadPublicExposureRecord(ctx context.Context, db *sql.DB, caseRef string) (publicExposureRecord, error) {
	if db == nil {
		return publicExposureRecord{}, sql.ErrConnDone
	}
	caseRef = strings.TrimSpace(caseRef)
	if !publicDossierCaseRefPattern.MatchString(caseRef) {
		return publicExposureRecord{}, errPublicExposureNotAuthorized
	}

	var canonical []byte
	var storedHash string
	var title, summary, profile, publishedBy string
	var featured bool
	var publishedAt sql.NullTime
	var readback publicationLedgerReadback
	err := db.QueryRowContext(ctx, `
		SELECT e.canonical_bundle,e.bundle_hash,
		       p.public_title,p.public_summary,p.featured,p.redaction_profile,p.published_at,p.published_by,
		       p.transition_id::text,
		       pe.transition_id::text,pe.case_ref,pe.actor,pe.action,
		       pe.publication_state->>'status',pe.publication_state->>'published_by',
		       pe.publication_state->>'public_title',pe.publication_state->>'public_summary',
		       pe.publication_state->>'redaction_profile',pe.publication_state->>'featured'
		FROM dossier_publications p
		JOIN dossier_exports e ON e.case_ref=p.case_ref
		LEFT JOIN dossier_publication_events pe ON pe.transition_id=p.transition_id
		WHERE p.case_ref=$1 AND p.status='public'`, caseRef).Scan(
		&canonical, &storedHash,
		&title, &summary, &featured, &profile, &publishedAt, &publishedBy,
		&readback.TransitionID,
		&readback.EventTransitionID, &readback.EventCaseRef, &readback.EventActor, &readback.EventAction,
		&readback.EventStatus, &readback.EventPublishedBy, &readback.EventTitle, &readback.EventSummary,
		&readback.EventProfile, &readback.EventFeatured,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return publicExposureRecord{}, errPublicExposureNotAuthorized
		}
		return publicExposureRecord{}, err
	}
	if !publishedAt.Valid {
		return publicExposureRecord{}, fmt.Errorf("%w: publication timestamp is unavailable", errPublicExposureIntegrity)
	}

	ledgerStatus, publicationAction, err := verifyPublicationLedgerReadback(
		caseRef, "public", title, summary, profile, publishedBy, featured, readback,
	)
	if err != nil {
		return publicExposureRecord{}, fmt.Errorf("%w: publication ledger mismatch", errPublicExposureNotAuthorized)
	}
	bundle, err := verifyStoredDossierBundle(canonical, caseRef, storedHash)
	if err != nil {
		return publicExposureRecord{}, fmt.Errorf("%w: %v", errPublicExposureIntegrity, err)
	}
	return publicExposureRecord{
		Bundle:            bundle,
		Title:             title,
		Summary:           summary,
		Featured:          featured,
		PublishedAt:       publishedAt.Time,
		PublishedBy:       publishedBy,
		LedgerStatus:      ledgerStatus,
		PublicationAction: publicationAction,
	}, nil
}

func publicExposureNotAuthorized(err error) bool {
	return errors.Is(err, errPublicExposureNotAuthorized)
}

func publicExposureIntegrityFailed(err error) bool {
	return errors.Is(err, errPublicExposureIntegrity)
}

func applyPublicExposureHeaders(w http.ResponseWriter, record publicExposureRecord) {
	w.Header().Set("X-Koschei-Publication-Ledger", record.LedgerStatus)
	w.Header().Set("X-Koschei-Published-By", record.PublishedBy)
	// The dossier bytes may be immutable, but public visibility is revocable.
	// Revalidation preserves ETag efficiency without allowing a stale cache to
	// outlive a later owner hide/draft transition.
	w.Header().Set("Cache-Control", "public, max-age=0, must-revalidate")
}
