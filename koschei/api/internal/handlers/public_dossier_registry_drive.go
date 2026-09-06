package handlers

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"koschei/api/internal/archive"
)

const publicCaseRegistryDriveObjectName = "koschei-public-case-registry-v1.json"

type publicDossierRegistrySnapshot struct {
	OK                         bool                  `json:"ok"`
	SchemaVersion              string                `json:"schema_version"`
	GeneratedAt                time.Time             `json:"generated_at"`
	RegistryStatus             string                `json:"registry_status"`
	RegistryComplete           bool                  `json:"registry_complete"`
	PublicationLedgerStatus    string                `json:"publication_ledger_status"`
	PublicationLedgerComplete  bool                  `json:"publication_ledger_complete"`
	TotalPublications          int                   `json:"total_publications"`
	InspectedPublications      int                   `json:"inspected_publications"`
	InvalidPublications        int                   `json:"invalid_publications"`
	UninspectedPublications    int                   `json:"uninspected_publications"`
	LedgerVerifiedPublications int                   `json:"ledger_verified_publications"`
	LegacyUnlinkedPublications int                   `json:"legacy_unlinked_publications"`
	InvalidLedgerPublications  int                   `json:"invalid_ledger_publications"`
	Count                      int                   `json:"count"`
	PublicationPolicy          map[string]any        `json:"publication_policy"`
	Cases                      []publicDossierCaseV2 `json:"cases"`
}

// PublicDossierCasesPortable preserves the primary-database security contract when
// the database is available, but can serve a checksum-verified immutable registry
// snapshot from Google Drive when the runtime is intentionally stateless.
func (h *Handler) PublicDossierCasesPortable(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	limit := publicDossierLimit(r.URL.Query().Get("limit"), 24, 100)

	if h != nil && h.DB != nil {
		if loaded, err := h.loadPublicDossierCasesV2(r, limit); err == nil {
			snapshot := publicDossierRegistrySnapshotFromLoad(loaded, time.Now().UTC())
			writePublicDossierRegistrySnapshot(w, snapshot, "primary_database", "")
			return
		}
	}

	snapshot, object, err := loadPublicDossierRegistrySnapshotFromDrive(r, limit)
	if err != nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"ok":                   false,
			"error":                "public_cases_unavailable",
			"registry_backend":     "google_drive",
			"configuration_status": publicDossierRegistryDriveConfigurationStatus(),
			"cases":                []publicDossierCaseV2{},
		})
		return
	}
	writePublicDossierRegistrySnapshot(w, snapshot, "google_drive", object.Hash)
}

func publicDossierRegistrySnapshotFromLoad(loaded publicDossierCasesV2Load, generatedAt time.Time) publicDossierRegistrySnapshot {
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
	return publicDossierRegistrySnapshot{
		OK:                         true,
		SchemaVersion:              publicCaseRegistrySchemaVersion,
		GeneratedAt:                generatedAt.UTC(),
		RegistryStatus:             registryStatus,
		RegistryComplete:           complete,
		PublicationLedgerStatus:    ledgerStatus,
		PublicationLedgerComplete:  ledgerComplete,
		TotalPublications:          loaded.TotalPublications,
		InspectedPublications:      loaded.InspectedPublications,
		InvalidPublications:        loaded.InvalidPublications,
		UninspectedPublications:    loaded.UninspectedPublications,
		LedgerVerifiedPublications: loaded.LedgerVerifiedPublications,
		LegacyUnlinkedPublications: loaded.LegacyUnlinkedPublications,
		InvalidLedgerPublications:  loaded.InvalidLedgerPublications,
		Count:                      len(loaded.Cases),
		PublicationPolicy: map[string]any{
			"deterministic_autopublish_supported":      true,
			"owner_publication_decisions_preserved":    true,
			"private_customer_investigations_excluded": true,
			"identity_or_wrongdoing_claim":             false,
			"immutable_source_bundle":                  true,
			"canonical_bundle_hash_reverified":         true,
			"publication_ledger_readback_verified":     true,
			"publication_effective_time_event_backed":  true,
			"db_owned_publication_time_v1":             true,
			"legacy_publication_lineage_declared":      true,
			"legacy_bundle_bytes_hash_verified":        true,
			"transition_identifiers_public":            false,
			"partial_registry_declared":                true,
			"drive_snapshot_checksum_verified":         true,
		},
		Cases: loaded.Cases,
	}
}

func loadPublicDossierRegistrySnapshotFromDrive(r *http.Request, limit int) (publicDossierRegistrySnapshot, archive.DriveObject, error) {
	drive, err := archive.NewGoogleDriveFromEnv()
	if err != nil {
		return publicDossierRegistrySnapshot{}, archive.DriveObject{}, err
	}
	object, payload, err := drive.GetLatestJSONByName(r.Context(), publicCaseRegistryDriveObjectName)
	if err != nil {
		return publicDossierRegistrySnapshot{}, archive.DriveObject{}, err
	}
	snapshot, err := parsePublicDossierRegistrySnapshot(payload, limit)
	if err != nil {
		return publicDossierRegistrySnapshot{}, archive.DriveObject{}, err
	}
	return snapshot, object, nil
}

func parsePublicDossierRegistrySnapshot(payload []byte, limit int) (publicDossierRegistrySnapshot, error) {
	var snapshot publicDossierRegistrySnapshot
	if err := json.Unmarshal(payload, &snapshot); err != nil {
		return snapshot, fmt.Errorf("invalid public registry snapshot JSON: %w", err)
	}
	if !snapshot.OK || snapshot.SchemaVersion != publicCaseRegistrySchemaVersion {
		return snapshot, errors.New("public registry snapshot schema contract mismatch")
	}
	if snapshot.GeneratedAt.IsZero() {
		return snapshot, errors.New("public registry snapshot generated_at is required")
	}
	if snapshot.Count != len(snapshot.Cases) {
		return snapshot, errors.New("public registry snapshot count mismatch")
	}
	seen := make(map[string]struct{}, len(snapshot.Cases))
	for _, item := range snapshot.Cases {
		if !publicDossierCaseRefPattern.MatchString(strings.TrimSpace(item.CaseRef)) {
			return snapshot, errors.New("public registry snapshot contains invalid case_ref")
		}
		if strings.TrimSpace(item.BundleHash) == "" {
			return snapshot, errors.New("public registry snapshot contains case without immutable bundle hash")
		}
		if _, exists := seen[item.CaseRef]; exists {
			return snapshot, errors.New("public registry snapshot contains duplicate case_ref")
		}
		seen[item.CaseRef] = struct{}{}
	}
	if limit < 0 {
		limit = 0
	}
	if limit > 0 && len(snapshot.Cases) > limit {
		snapshot.Cases = append([]publicDossierCaseV2(nil), snapshot.Cases[:limit]...)
		snapshot.Count = len(snapshot.Cases)
	}
	return snapshot, nil
}

func writePublicDossierRegistrySnapshot(w http.ResponseWriter, snapshot publicDossierRegistrySnapshot, backend, objectHash string) {
	w.Header().Set("X-Koschei-Registry-Complete", fmt.Sprintf("%t", snapshot.RegistryComplete))
	response := map[string]any{
		"ok":                           snapshot.OK,
		"schema_version":               snapshot.SchemaVersion,
		"generated_at":                 snapshot.GeneratedAt,
		"registry_status":              snapshot.RegistryStatus,
		"registry_complete":            snapshot.RegistryComplete,
		"publication_ledger_status":    snapshot.PublicationLedgerStatus,
		"publication_ledger_complete":  snapshot.PublicationLedgerComplete,
		"total_publications":           snapshot.TotalPublications,
		"inspected_publications":       snapshot.InspectedPublications,
		"invalid_publications":         snapshot.InvalidPublications,
		"uninspected_publications":     snapshot.UninspectedPublications,
		"ledger_verified_publications": snapshot.LedgerVerifiedPublications,
		"legacy_unlinked_publications": snapshot.LegacyUnlinkedPublications,
		"invalid_ledger_publications":  snapshot.InvalidLedgerPublications,
		"count":                        snapshot.Count,
		"publication_policy":           snapshot.PublicationPolicy,
		"registry_backend":             backend,
		"cases":                        snapshot.Cases,
	}
	if strings.TrimSpace(objectHash) != "" {
		response["registry_object_sha256"] = strings.ToLower(strings.TrimSpace(objectHash))
	}
	writeJSON(w, http.StatusOK, response)
}

func publicDossierRegistryDriveConfigurationStatus() string {
	folder := strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_ARCHIVE_FOLDER_ID")) != ""
	credential := strings.TrimSpace(os.Getenv("GOOGLE_DRIVE_SERVICE_ACCOUNT_JSON")) != ""
	switch {
	case folder && credential:
		return "configured"
	case folder:
		return "missing_service_account_credential"
	case credential:
		return "missing_archive_folder"
	default:
		return "not_configured"
	}
}

// OwnerPublicDossierRegistrySync writes a checksum-addressed Drive snapshot of
// the current verified publication registry. It never accepts registry bytes
// from the client and never mutates dossier evidence.
func (h *Handler) OwnerPublicDossierRegistrySync(w http.ResponseWriter, r *http.Request) {
	if h == nil || h.DB == nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Dossier publication database is unavailable")
		return
	}
	loaded, err := h.loadPublicDossierCasesV2(r, 100)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Public dossier registry could not be loaded")
		return
	}
	snapshot := publicDossierRegistrySnapshotFromLoad(loaded, time.Now().UTC())
	payload, err := json.Marshal(snapshot)
	if err != nil {
		writeAPIError(w, http.StatusInternalServerError, APICodeInternalError, "Public dossier registry snapshot could not be encoded")
		return
	}
	drive, err := archive.NewGoogleDriveFromEnv()
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Google Drive public registry archive is unavailable")
		return
	}
	object, err := drive.PutJSON(r.Context(), publicCaseRegistryDriveObjectName, payload)
	if err != nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Public dossier registry snapshot could not be archived")
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"ok":                         true,
		"schema_version":             publicCaseRegistrySchemaVersion,
		"registry_backend":           "google_drive",
		"registry_object_id":         object.ID,
		"registry_object_sha256":     object.Hash,
		"count":                      snapshot.Count,
		"generated_at":               snapshot.GeneratedAt,
		"immutable_evidence_unchanged": true,
	})
}
