package handlers

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strconv"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func publicDiscoveryIntegrityFixture(t *testing.T, caseRef string) (dossierBundle, []byte) {
	t.Helper()
	bundle, _ := integrityFixture(t)
	bundle.CaseRef = caseRef
	bodyBytes, err := json.Marshal(bundle.dossierBody)
	if err != nil {
		t.Fatalf("marshal public discovery dossier body: %v", err)
	}
	bundle.BundleHash = dossierSHA256(bodyBytes)
	canonical, err := json.Marshal(bundle)
	if err != nil {
		t.Fatalf("marshal public discovery dossier bundle: %v", err)
	}
	return bundle, canonical
}

func TestPublicDossierCasesV2RevokesDiscoveryAfterHidePostgres17(t *testing.T) {
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

	const caseRef = "KD1-ffffffffffffffffffffffffffffffff"
	bundle, canonical := publicDiscoveryIntegrityFixture(t, caseRef)
	suffix := strconv.FormatInt(time.Now().UnixNano(), 10)
	verdictSignature := "public-discovery-" + suffix
	mint := "discovery-mint-" + suffix
	const sourceHash = "sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"
	var sourceID string
	if err := db.QueryRowContext(ctx, `
		INSERT INTO dossier_source_snapshots
			(mint,network,verdict_signature,ruleset_version,produced_at,source_hash,canonical_source,source_payload)
		VALUES ($1,'solana-mainnet',$2,'discovery-test-v1',now(),$3,convert_to('{}','UTF8'),'{}'::jsonb)
		RETURNING id::text`, mint, verdictSignature, sourceHash).Scan(&sourceID); err != nil {
		t.Fatalf("insert source snapshot: %v", err)
	}
	if _, err := db.ExecContext(ctx, `
		INSERT INTO dossier_exports
			(case_ref,mint,verdict_signature,source_snapshot_id,bundle_hash,canonical_bundle,bundle_json,requested_by)
		VALUES ($1,$2,$3,$4::uuid,$5,$6,$7::jsonb,'public-discovery-test')`,
		caseRef, mint, verdictSignature, sourceID, bundle.BundleHash, canonical, string(canonical)); err != nil {
		t.Fatalf("insert immutable dossier export: %v", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin publish transition: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO dossier_publications
			(case_ref,status,public_title,public_summary,featured,redaction_profile,published_at,published_by,created_at,updated_at)
		VALUES ($1,'public','Discovery revocation case','Ledger-backed discovery authorization',false,$2,now(),'owner',now(),now())`,
		caseRef, publicDossierRedactionProfile); err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert public discovery state: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO dossier_publication_events (case_ref,action,actor,publication_state)
		VALUES ($1,'publish','owner','{}'::jsonb)`, caseRef); err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert publish event: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit public discovery transition: %v", err)
	}

	h := &Handler{DB: db}
	assertRegistry := func(wantVisible bool) {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/public/cases?limit=100", nil)
		recorder := httptest.NewRecorder()
		h.PublicDossierCasesV2(recorder, req)
		if recorder.Code != http.StatusOK {
			t.Fatalf("public registry status=%d body=%s", recorder.Code, recorder.Body.String())
		}
		if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
			t.Fatalf("public discovery cache contract=%q want no-store", got)
		}
		var payload struct {
			Cases []publicDossierCaseV2 `json:"cases"`
		}
		if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
			t.Fatalf("decode public registry: %v", err)
		}
		visible := false
		for _, item := range payload.Cases {
			if item.CaseRef == caseRef {
				visible = true
				if item.PublicationLedgerStatus != publicationLedgerVerified {
					t.Fatalf("published discovery case lineage=%q want verified", item.PublicationLedgerStatus)
				}
			}
		}
		if visible != wantVisible {
			t.Fatalf("public discovery visibility=%v want=%v", visible, wantVisible)
		}
	}

	assertRegistry(true)

	tx, err = db.BeginTx(ctx, nil)
	if err != nil {
		t.Fatalf("begin hide transition: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE dossier_publications
		SET status='hidden',featured=false,updated_at=now(),published_by='owner'
		WHERE case_ref=$1`, caseRef); err != nil {
		_ = tx.Rollback()
		t.Fatalf("hide public discovery state: %v", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO dossier_publication_events (case_ref,action,actor,publication_state)
		VALUES ($1,'hide','owner','{}'::jsonb)`, caseRef); err != nil {
		_ = tx.Rollback()
		t.Fatalf("insert hide event: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit hidden discovery transition: %v", err)
	}

	assertRegistry(false)
}
