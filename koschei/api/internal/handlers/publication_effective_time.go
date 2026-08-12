package handlers

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

const (
	publicationTimeContractDBOwnedV1 = "db-owned-v1"
	publicationTimeDBVerified        = "db_verified"
	publicationTimeLegacyEvent       = "legacy_event"
	publicationTimeLegacyColumn      = "legacy_column"
)

type publicationEffectiveTimeReadback struct {
	PublishEventAt           sql.NullTime
	PublishEventTransitionID sql.NullString
	PublishEventContract     sql.NullString
}

// resolvePublicationEffectiveTime prefers the immutable publish event over the
// mutable publication row. New db-owned-v1 events are cross-checked against the
// row's published_at value; older events and eventless legacy rows remain usable
// but are explicitly labeled instead of being upgraded to verified provenance.
func resolvePublicationEffectiveTime(storedPublishedAt sql.NullTime, readback publicationEffectiveTimeReadback) (time.Time, string, error) {
	if readback.PublishEventAt.Valid && !readback.PublishEventAt.Time.IsZero() {
		contract := strings.TrimSpace(readback.PublishEventContract.String)
		switch contract {
		case publicationTimeContractDBOwnedV1:
			if !readback.PublishEventTransitionID.Valid || strings.TrimSpace(readback.PublishEventTransitionID.String) == "" {
				return time.Time{}, "", fmt.Errorf("db-owned publication time is missing its linked transition")
			}
			if !storedPublishedAt.Valid || storedPublishedAt.Time.IsZero() {
				return time.Time{}, "", fmt.Errorf("db-owned publication time is missing current publication timestamp")
			}
			if !storedPublishedAt.Time.Equal(readback.PublishEventAt.Time) {
				return time.Time{}, "", fmt.Errorf("db-owned publication timestamp does not match immutable publish event")
			}
			return readback.PublishEventAt.Time.UTC(), publicationTimeDBVerified, nil
		case "":
			return readback.PublishEventAt.Time.UTC(), publicationTimeLegacyEvent, nil
		default:
			return time.Time{}, "", fmt.Errorf("unsupported publication time contract %q", contract)
		}
	}
	if storedPublishedAt.Valid && !storedPublishedAt.Time.IsZero() {
		return storedPublishedAt.Time.UTC(), publicationTimeLegacyColumn, nil
	}
	return time.Time{}, "", fmt.Errorf("publication effective time is unavailable")
}
