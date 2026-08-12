package handlers

import (
	"database/sql"
	"testing"
	"time"
)

func TestResolvePublicationEffectiveTimeAcceptsDBOwnedEvent(t *testing.T) {
	at := time.Date(2026, 8, 12, 1, 2, 3, 0, time.UTC)
	resolved, status, err := resolvePublicationEffectiveTime(
		sql.NullTime{Time: at, Valid: true},
		publicationEffectiveTimeReadback{
			PublishEventAt:           sql.NullTime{Time: at, Valid: true},
			PublishEventTransitionID: sql.NullString{String: "11111111-1111-1111-1111-111111111111", Valid: true},
			PublishEventContract:     sql.NullString{String: publicationTimeContractDBOwnedV1, Valid: true},
		},
	)
	if err != nil {
		t.Fatalf("resolve db-owned publication time: %v", err)
	}
	if !resolved.Equal(at) || status != publicationTimeDBVerified {
		t.Fatalf("unexpected db-owned time resolution: time=%s status=%q", resolved, status)
	}
}

func TestResolvePublicationEffectiveTimeRejectsDBOwnedMismatch(t *testing.T) {
	stored := time.Date(2026, 8, 12, 1, 2, 3, 0, time.UTC)
	event := stored.Add(time.Second)
	if _, _, err := resolvePublicationEffectiveTime(
		sql.NullTime{Time: stored, Valid: true},
		publicationEffectiveTimeReadback{
			PublishEventAt:           sql.NullTime{Time: event, Valid: true},
			PublishEventTransitionID: sql.NullString{String: "11111111-1111-1111-1111-111111111111", Valid: true},
			PublishEventContract:     sql.NullString{String: publicationTimeContractDBOwnedV1, Valid: true},
		},
	); err == nil {
		t.Fatal("db-owned publication timestamp mismatch was accepted")
	}
}

func TestResolvePublicationEffectiveTimeDeclaresLegacyEvent(t *testing.T) {
	stored := time.Date(2026, 8, 10, 1, 0, 0, 0, time.UTC)
	event := time.Date(2026, 8, 11, 2, 0, 0, 0, time.UTC)
	resolved, status, err := resolvePublicationEffectiveTime(
		sql.NullTime{Time: stored, Valid: true},
		publicationEffectiveTimeReadback{PublishEventAt: sql.NullTime{Time: event, Valid: true}},
	)
	if err != nil {
		t.Fatalf("resolve legacy event time: %v", err)
	}
	if !resolved.Equal(event) || status != publicationTimeLegacyEvent {
		t.Fatalf("unexpected legacy event resolution: time=%s status=%q", resolved, status)
	}
}

func TestResolvePublicationEffectiveTimeFallsBackToLegacyColumn(t *testing.T) {
	stored := time.Date(2026, 8, 9, 1, 0, 0, 0, time.UTC)
	resolved, status, err := resolvePublicationEffectiveTime(sql.NullTime{Time: stored, Valid: true}, publicationEffectiveTimeReadback{})
	if err != nil {
		t.Fatalf("resolve legacy column time: %v", err)
	}
	if !resolved.Equal(stored) || status != publicationTimeLegacyColumn {
		t.Fatalf("unexpected legacy column resolution: time=%s status=%q", resolved, status)
	}
}

func TestResolvePublicationEffectiveTimeRejectsUnknownContract(t *testing.T) {
	at := time.Date(2026, 8, 12, 1, 2, 3, 0, time.UTC)
	if _, _, err := resolvePublicationEffectiveTime(
		sql.NullTime{Time: at, Valid: true},
		publicationEffectiveTimeReadback{
			PublishEventAt:       sql.NullTime{Time: at, Valid: true},
			PublishEventContract: sql.NullString{String: "future-contract", Valid: true},
		},
	); err == nil {
		t.Fatal("unknown publication time contract was accepted")
	}
}
