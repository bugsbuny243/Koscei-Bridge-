package handlers

import (
	"context"
	"database/sql"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestApplyPublicExposureHeadersRequiresRevalidation(t *testing.T) {
	recorder := httptest.NewRecorder()
	applyPublicExposureHeaders(recorder, publicExposureRecord{
		LedgerStatus:          publicationLedgerVerified,
		PublicationTimeStatus: publicationTimeDBVerified,
		PublishedBy:           "owner",
	})
	if got := recorder.Header().Get("Cache-Control"); got != "public, max-age=0, must-revalidate" {
		t.Fatalf("unexpected revocable exposure cache contract: %q", got)
	}
	if got := recorder.Header().Get("X-Koschei-Publication-Ledger"); got != publicationLedgerVerified {
		t.Fatalf("unexpected publication ledger header: %q", got)
	}
	if got := recorder.Header().Get("X-Koschei-Publication-Time"); got != publicationTimeDBVerified {
		t.Fatalf("unexpected publication time header: %q", got)
	}
	if got := recorder.Header().Get("X-Koschei-Published-By"); got != "owner" {
		t.Fatalf("unexpected publisher header: %q", got)
	}
	if got := recorder.Header().Get("X-Koschei-Transition-ID"); got != "" {
		t.Fatalf("internal transition identifier leaked through response headers: %q", got)
	}
}

func TestLoadPublicExposureRecordRevokesAfterHidePostgres17(t *testing.T) {
	databaseURL := os.Getenv("KOSCHEI_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KOSCHEI_TEST_DATABASE_URL is not configured")
	}
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		t.Fatalf("open postgres: %v", err)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatalf("ping postgres: %v", err)
	}

	bundle, canonical := integrityFixture(t)
	caseRef := bundle.CaseRef
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	verdictSignature := "public-exposure-" + suffix
	const sourceHash = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	var sourceID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO dossier_source_snapshots
			(mint,network,verdict_signature,ruleset_version,produced_at,source_hash,canonical_source,source_payload)
		VALUES ($1,'solana-mainnet',$2,'exposure-test-v1',now(),$3,convert_to('{}','UTF8'),'{}'::jsonb)
		RETURNING id::text`, "exposure-mint-"+suffix, verdictSignature, sourceHash).Scan(&sourceID); err != nil {
		t.Fatalf("insert source snapshot: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO dossier_exports
			(case_ref,mint,verdict_signature,source_snapshot_id,bundle_hash,canonical_bundle,bundle_json,requested_by)
		VALUES ($1,$2,$3,$4::uuid,$5,$6,$7::jsonb,'public-exposure-test')`,
		caseRef, "exposure-mint-"+suffix, verdictSignature, sourceID, bundle.BundleHash, canonical, string(canonical)); err != nil {
		t.Fatalf("insert immutable dossier export: %v", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin publish transition: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO dossier_publications
			(case_ref,status,public_title,public_summary,featured,redaction_profile,published_at,published_by,created_at,updated_at)
		VALUES ($1,'public','Direct exposure case','Ledger-backed public authorization',false,$2,now(),'owner',now(),now())`,
		caseRef, publicDossierRedactionProfile); err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert publication: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO dossier_publication_events (case_ref,action,actor,publication_state)
		VALUES ($1,'publish','owner','{}'::jsonb)`, caseRef); err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert publish event: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit publish transition: %v", err)
	}

	record, err := loadPublicExposureRecord(ctx, db, caseRef)
	if err != nil {
		t.Fatalf("load authorized public exposure: %v", err)
	}
	if record.LedgerStatus != publicationLedgerVerified || record.PublishedBy != "owner" || record.PublicationAction != "publish" {
		t.Fatalf("unexpected public exposure provenance: %#v", record)
	}
	if record.PublicationTimeStatus != publicationTimeDBVerified {
		t.Fatalf("unexpected public exposure time provenance: %q", record.PublicationTimeStatus)
	}
	if record.Bundle.BundleHash != bundle.BundleHash {
		t.Fatalf("direct exposure bundle changed: got %q want %q", record.Bundle.BundleHash, bundle.BundleHash)
	}

	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin hide transition: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE dossier_publications
		SET status='hidden',featured=false,updated_at=now(),published_by='owner'
		WHERE case_ref=$1`, caseRef); err != nil {
		_ = tx.Rollback()
		t.Fatalf("hide publication: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO dossier_publication_events (case_ref,action,actor,publication_state)
		VALUES ($1,'hide','owner','{}'::jsonb)`, caseRef); err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert hide event: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit hide transition: %v", err)
	}

	if _, err := loadPublicExposureRecord(ctx, db, caseRef); !publicExposureNotAuthorized(err) {
		t.Fatalf("hidden publication remained directly accessible: %v", err)
	}
}
