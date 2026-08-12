package handlers

import (
	"database/sql"
	"fmt"
	"strings"
)

const (
	publicationLedgerVerified       = "verified"
	publicationLedgerLegacyUnlinked = "legacy_unlinked"
)

type publicationLedgerReadback struct {
	TransitionID      sql.NullString
	EventTransitionID sql.NullString
	EventCaseRef      sql.NullString
	EventActor        sql.NullString
	EventAction       sql.NullString
	EventStatus       sql.NullString
	EventPublishedBy  sql.NullString
	EventTitle        sql.NullString
	EventSummary      sql.NullString
	EventProfile      sql.NullString
	EventFeatured     sql.NullString
}

func verifyPublicationLedgerReadback(
	caseRef, status, title, summary, profile, publishedBy string,
	featured bool,
	readback publicationLedgerReadback,
) (string, string, error) {
	transitionID := strings.TrimSpace(readback.TransitionID.String)
	if !readback.TransitionID.Valid || transitionID == "" {
		return publicationLedgerLegacyUnlinked, "", nil
	}

	eventTransitionID := strings.TrimSpace(readback.EventTransitionID.String)
	if !readback.EventTransitionID.Valid || eventTransitionID == "" || eventTransitionID != transitionID {
		return "", "", fmt.Errorf("publication ledger transition event is missing or mismatched")
	}
	if !readback.EventCaseRef.Valid || strings.TrimSpace(readback.EventCaseRef.String) != strings.TrimSpace(caseRef) {
		return "", "", fmt.Errorf("publication ledger case_ref mismatch")
	}

	expectedActor := ""
	switch strings.TrimSpace(publishedBy) {
	case "owner":
		expectedActor = "owner"
	case autopublishPublishedBy:
		expectedActor = autopublishActor
	default:
		return "", "", fmt.Errorf("publication ledger publisher is unsupported")
	}
	if !readback.EventActor.Valid || strings.TrimSpace(readback.EventActor.String) != expectedActor {
		return "", "", fmt.Errorf("publication ledger actor does not match publisher")
	}

	action := strings.TrimSpace(readback.EventAction.String)
	if !readback.EventAction.Valid || action == "" {
		return "", "", fmt.Errorf("publication ledger action is missing")
	}
	switch action {
	case "publish", "hide", "feature", "unfeature", "update", "draft":
	default:
		return "", "", fmt.Errorf("publication ledger action is invalid")
	}

	expectedFeatured := "false"
	if featured {
		expectedFeatured = "true"
	}
	checks := []struct {
		name     string
		value    sql.NullString
		expected string
	}{
		{name: "status", value: readback.EventStatus, expected: status},
		{name: "published_by", value: readback.EventPublishedBy, expected: publishedBy},
		{name: "public_title", value: readback.EventTitle, expected: title},
		{name: "public_summary", value: readback.EventSummary, expected: summary},
		{name: "redaction_profile", value: readback.EventProfile, expected: profile},
		{name: "featured", value: readback.EventFeatured, expected: expectedFeatured},
	}
	for _, check := range checks {
		if !check.value.Valid || check.value.String != check.expected {
			return "", "", fmt.Errorf("publication ledger %s snapshot mismatch", check.name)
		}
	}
	return publicationLedgerVerified, action, nil
}
