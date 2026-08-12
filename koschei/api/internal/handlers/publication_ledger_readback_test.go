package handlers

import (
	"database/sql"
	"testing"
)

func linkedPublicationLedgerFixture() publicationLedgerReadback {
	return publicationLedgerReadback{
		TransitionID:      sql.NullString{String: "11111111-1111-1111-1111-111111111111", Valid: true},
		EventTransitionID: sql.NullString{String: "11111111-1111-1111-1111-111111111111", Valid: true},
		EventCaseRef:      sql.NullString{String: "KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Valid: true},
		EventActor:        sql.NullString{String: "owner", Valid: true},
		EventAction:       sql.NullString{String: "publish", Valid: true},
		EventStatus:       sql.NullString{String: "public", Valid: true},
		EventPublishedBy:  sql.NullString{String: "owner", Valid: true},
		EventTitle:        sql.NullString{String: "Case", Valid: true},
		EventSummary:      sql.NullString{String: "Summary", Valid: true},
		EventProfile:      sql.NullString{String: publicDossierRedactionProfile, Valid: true},
		EventFeatured:     sql.NullString{String: "false", Valid: true},
	}
}

func TestVerifyPublicationLedgerReadbackAcceptsLinkedOwnerTransition(t *testing.T) {
	status, action, err := verifyPublicationLedgerReadback(
		"KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "public", "Case", "Summary",
		publicDossierRedactionProfile, "owner", false, linkedPublicationLedgerFixture(),
	)
	if err != nil {
		t.Fatalf("verify linked owner transition: %v", err)
	}
	if status != publicationLedgerVerified || action != "publish" {
		t.Fatalf("unexpected linked readback: status=%q action=%q", status, action)
	}
}

func TestVerifyPublicationLedgerReadbackDeclaresLegacyUnlinked(t *testing.T) {
	status, action, err := verifyPublicationLedgerReadback(
		"KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "public", "Case", "Summary",
		publicDossierRedactionProfile, "owner", false, publicationLedgerReadback{},
	)
	if err != nil {
		t.Fatalf("legacy row should remain readable: %v", err)
	}
	if status != publicationLedgerLegacyUnlinked || action != "" {
		t.Fatalf("unexpected legacy readback: status=%q action=%q", status, action)
	}
}

func TestVerifyPublicationLedgerReadbackRejectsSnapshotMismatch(t *testing.T) {
	readback := linkedPublicationLedgerFixture()
	readback.EventSummary.String = "tampered"
	if _, _, err := verifyPublicationLedgerReadback(
		"KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "public", "Case", "Summary",
		publicDossierRedactionProfile, "owner", false, readback,
	); err == nil {
		t.Fatal("mismatched immutable event snapshot was accepted")
	}
}

func TestVerifyPublicationLedgerReadbackRejectsActorPublisherMismatch(t *testing.T) {
	readback := linkedPublicationLedgerFixture()
	readback.EventActor.String = autopublishActor
	if _, _, err := verifyPublicationLedgerReadback(
		"KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "public", "Case", "Summary",
		publicDossierRedactionProfile, "owner", false, readback,
	); err == nil {
		t.Fatal("actor/publisher mismatch was accepted")
	}
}

func TestVerifyPublicationLedgerReadbackAcceptsAutopublishIdentity(t *testing.T) {
	readback := linkedPublicationLedgerFixture()
	readback.EventActor.String = autopublishActor
	readback.EventPublishedBy.String = autopublishPublishedBy
	status, _, err := verifyPublicationLedgerReadback(
		"KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "public", "Case", "Summary",
		publicDossierRedactionProfile, autopublishPublishedBy, false, readback,
	)
	if err != nil {
		t.Fatalf("verify linked autopublish transition: %v", err)
	}
	if status != publicationLedgerVerified {
		t.Fatalf("unexpected autopublish ledger status: %q", status)
	}
}
