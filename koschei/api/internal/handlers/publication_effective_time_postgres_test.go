package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"strconv"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestPublicationEffectiveTimeLifecyclePostgres17(t *testing.T) {
	databaseURL := os.Getenv("KOSCHEI_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KOSCHEI_TEST_DATABASE_URL is not configured")
	}
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}

	const caseRef = "KD1-gggggggggggggggggggggggggggggggg"
	bundle, _ := integrityFixture(t)
	bundle.CaseRef = caseRef
	bodyBytes, err := json.Marshal(bundle.dossierBody)
	if err != nil {
		t.Fatalf("marshal dossier body: %v", err)
	}
	bundle.BundleHash = dossierSHA256(bodyBytes)
	canonical, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal dossier bundle: %v", err)
	}

	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	mint := "effective-time-mint-" + suffix
	verdictSignature := "effective-time-" + suffix
	const sourceHash = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	var sourceID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO dossier_source_snapshots
			(mint,network,verdict_signature,ruleset_version,produced_at,source_hash,canonical_source,source_payload)
		VALUES ($1,'solana-mainnet',$2,'effective-time-v1',now(),$3,convert_to('{}','UTF8'),'{}'::jsonb)
		RETURNING id::text`, mint, verdictSignature, sourceHash).Scan(&sourceID); err != nil {
		t.Fatalf("insert source snapshot: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO dossier_exports
			(case_ref,mint,verdict_signature,source_snapshot_id,bundle_hash,canonical_bundle,bundle_json,requested_by)
		VALUES ($1,$2,$3,$4::uuid,$5,$6,$7::jsonb,'effective-time-test')`,
		caseRef, mint, verdictSignature, sourceID, bundle.BundleHash, canonical, string(canonical)); err != nil {
		t.Fatalf("insert immutable dossier export: %v", err)
	}

	bogusPublicationAt := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	bogusEventAt := time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)

	publish := func(action string, mutate func(*sql.Tx) error) {
		t.Helper()
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			t.Fatalf("begin %s transition: %v", action, err)
		}
		if err := mutate(tx); err != nil {
			_ = tx.Rollback()
			t.Fatalf("mutate %s transition: %v", action, err)
		}
		if _, err := tx.ExecContext(ctx, `
			INSERT INTO dossier_publication_events (case_ref,action,actor,publication_state,created_at)
			VALUES ($1,$2,'owner','{}'::jsonb,$3)`, caseRef, action, bogusEventAt); err != nil {
			_ = tx.Rollback()
			t.Fatalf("insert %s event: %v", action, err)
		}
		if err := tx.Commit(); err != nil {
			t.Fatalf("commit %s transition: %v", action, err)
		}
	}

	publish("publish", func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			INSERT INTO dossier_publications
				(case_ref,status,public_title,public_summary,featured,redaction_profile,published_at,published_by,created_at,updated_at)
			VALUES ($1,'public','Effective time case','First public interval',false,$2,$3,'owner',now(),now())`,
			caseRef, publicDossierRedactionProfile, bogusPublicationAt)
		return err
	})

	loadTimes := func() (time.Time, time.Time, string, sql.NullString) {
		t.Helper()
		var storedAt, eventAt time.Time
		var contract string
		var transitionID sql.NullString
		if err := db.QueryRowContext(ctx, `
			SELECT p.published_at,e.created_at,e.publication_state->>'publication_time_contract',e.transition_id::text
			FROM dossier_publications p
			JOIN dossier_publication_events e ON e.case_ref=p.case_ref AND e.action='publish'
			WHERE p.case_ref=$1
			ORDER BY e.created_at DESC,e.id DESC
			LIMIT 1`, caseRef).Scan(&storedAt, &eventAt, &contract, &transitionID); err != nil {
			t.Fatalf("load publication time proof: %v", err)
		}
		return storedAt.UTC(), eventAt.UTC(), contract, transitionID
	}

	firstStoredAt, firstEventAt, firstContract, firstTransitionID := loadTimes()
	if !firstStoredAt.Equal(firstEventAt) {
		t.Fatalf("first public interval timestamp mismatch: state=%s event=%s", firstStoredAt, firstEventAt)
	}
	if firstStoredAt.Equal(bogusPublicationAt) || firstEventAt.Equal(bogusEventAt) {
		t.Fatal("caller-supplied publication timestamps were not replaced by PostgreSQL")
	}
	if firstContract != publicationTimeContractDBOwnedV1 || !firstTransitionID.Valid || firstTransitionID.String == "" {
		t.Fatalf("first public interval lacks db-owned time proof: contract=%q transition=%#v", firstContract, firstTransitionID)
	}

	record, err := loadPublicExposureRecord(ctx, db, caseRef)
	if err != nil {
		t.Fatalf("load first public exposure: %v", err)
	}
	if !record.PublishedAt.Equal(firstEventAt) || record.PublicationTimeStatus != publicationTimeDBVerified {
		t.Fatalf("unexpected first public exposure time: at=%s status=%q", record.PublishedAt, record.PublicationTimeStatus)
	}

	time.Sleep(20 * time.Millisecond)
	publish("update", func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE dossier_publications
			SET public_title='Effective time case v2',published_at=$2,updated_at=now()
			WHERE case_ref=$1`, caseRef, bogusPublicationAt)
		return err
	})
	storedAfterUpdate, _, _, _ := loadTimes()
	if !storedAfterUpdate.Equal(firstStoredAt) {
		t.Fatalf("public metadata update rewrote exposure start: before=%s after=%s", firstStoredAt, storedAfterUpdate)
	}

	publish("hide", func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE dossier_publications
			SET status='hidden',featured=false,published_at=$2,updated_at=now()
			WHERE case_ref=$1`, caseRef, bogusPublicationAt)
		return err
	})
	var hiddenStoredAt time.Time
	if err := db.QueryRowContext(ctx, `SELECT published_at FROM dossier_publications WHERE case_ref=$1`, caseRef).Scan(&hiddenStoredAt); err != nil {
		t.Fatalf("load hidden publication time: %v", err)
	}
	if !hiddenStoredAt.UTC().Equal(firstStoredAt) {
		t.Fatalf("hide transition rewrote previous public interval start: before=%s after=%s", firstStoredAt, hiddenStoredAt.UTC())
	}

	time.Sleep(20 * time.Millisecond)
	publish("publish", func(tx *sql.Tx) error {
		_, err := tx.ExecContext(ctx, `
			UPDATE dossier_publications
			SET status='public',published_at=$2,updated_at=now()
			WHERE case_ref=$1`, caseRef, bogusPublicationAt)
		return err
	})
	secondStoredAt, secondEventAt, secondContract, secondTransitionID := loadTimes()
	if !secondStoredAt.Equal(secondEventAt) {
		t.Fatalf("republish timestamp mismatch: state=%s event=%s", secondStoredAt, secondEventAt)
	}
	if !secondStoredAt.After(firstStoredAt) {
		t.Fatalf("republish did not start a fresh public interval: first=%s second=%s", firstStoredAt, secondStoredAt)
	}
	if secondContract != publicationTimeContractDBOwnedV1 || !secondTransitionID.Valid || secondTransitionID.String == "" {
		t.Fatalf("republish lacks db-owned time proof: contract=%q transition=%#v", secondContract, secondTransitionID)
	}

	record, err = loadPublicExposureRecord(ctx, db, caseRef)
	if err != nil {
		t.Fatalf("load republished public exposure: %v", err)
	}
	if !record.PublishedAt.Equal(secondEventAt) || record.PublicationTimeStatus != publicationTimeDBVerified {
		t.Fatalf("unexpected republished exposure time: at=%s status=%q", record.PublishedAt, record.PublicationTimeStatus)
	}
}
