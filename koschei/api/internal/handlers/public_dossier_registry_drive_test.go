package handlers

import (
	"encoding/json"
	"testing"
	"time"
)

func validDriveRegistrySnapshotForTest() publicDossierRegistrySnapshot {
	caseRef := "KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	return publicDossierRegistrySnapshot{
		OK:                         true,
		SchemaVersion:              publicCaseRegistrySchemaVersion,
		GeneratedAt:                time.Date(2026, 9, 6, 18, 30, 0, 0, time.UTC),
		RegistryStatus:             "operational",
		RegistryComplete:           true,
		PublicationLedgerStatus:    "verified",
		PublicationLedgerComplete:  true,
		TotalPublications:          1,
		InspectedPublications:      1,
		LedgerVerifiedPublications: 1,
		Count:                      1,
		PublicationPolicy:          map[string]any{"immutable_source_bundle": true},
		Cases: []publicDossierCaseV2{{
			publicDossierCase: publicDossierCase{
				CaseRef:    caseRef,
				BundleHash: "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
			},
		}},
	}
}

func TestParsePublicDossierRegistrySnapshotAcceptsVerifiedSnapshot(t *testing.T) {
	snapshot := validDriveRegistrySnapshotForTest()
	payload, err := json.Marshal(snapshot)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := parsePublicDossierRegistrySnapshot(payload, 100)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed.Count != 1 || len(parsed.Cases) != 1 {
		t.Fatalf("unexpected parsed count: count=%d cases=%d", parsed.Count, len(parsed.Cases))
	}
}

func TestParsePublicDossierRegistrySnapshotAppliesReadLimit(t *testing.T) {
	snapshot := validDriveRegistrySnapshotForTest()
	second := snapshot.Cases[0]
	second.CaseRef = "KD1-bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	snapshot.Cases = append(snapshot.Cases, second)
	snapshot.Count = 2
	snapshot.TotalPublications = 2
	snapshot.InspectedPublications = 2
	snapshot.LedgerVerifiedPublications = 2
	payload, _ := json.Marshal(snapshot)
	parsed, err := parsePublicDossierRegistrySnapshot(payload, 1)
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if parsed.Count != 1 || len(parsed.Cases) != 1 {
		t.Fatalf("limit not applied: count=%d cases=%d", parsed.Count, len(parsed.Cases))
	}
}

func TestParsePublicDossierRegistrySnapshotRejectsCountMismatch(t *testing.T) {
	snapshot := validDriveRegistrySnapshotForTest()
	snapshot.Count = 2
	payload, _ := json.Marshal(snapshot)
	if _, err := parsePublicDossierRegistrySnapshot(payload, 100); err == nil {
		t.Fatal("expected count mismatch rejection")
	}
}

func TestParsePublicDossierRegistrySnapshotRejectsMissingBundleHash(t *testing.T) {
	snapshot := validDriveRegistrySnapshotForTest()
	snapshot.Cases[0].BundleHash = ""
	payload, _ := json.Marshal(snapshot)
	if _, err := parsePublicDossierRegistrySnapshot(payload, 100); err == nil {
		t.Fatal("expected missing bundle hash rejection")
	}
}

func TestParsePublicDossierRegistrySnapshotRejectsDuplicateCaseRef(t *testing.T) {
	snapshot := validDriveRegistrySnapshotForTest()
	snapshot.Cases = append(snapshot.Cases, snapshot.Cases[0])
	snapshot.Count = 2
	payload, _ := json.Marshal(snapshot)
	if _, err := parsePublicDossierRegistrySnapshot(payload, 100); err == nil {
		t.Fatal("expected duplicate case_ref rejection")
	}
}

func TestParsePublicDossierRegistrySnapshotRejectsSchemaMismatch(t *testing.T) {
	snapshot := validDriveRegistrySnapshotForTest()
	snapshot.SchemaVersion = "unknown-registry"
	payload, _ := json.Marshal(snapshot)
	if _, err := parsePublicDossierRegistrySnapshot(payload, 100); err == nil {
		t.Fatal("expected schema mismatch rejection")
	}
}
