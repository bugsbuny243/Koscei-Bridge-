package defense

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func TestCustomerProgramLabPostgres17(t *testing.T) {
	databaseURL := os.Getenv("KOSCHEI_TEST_DATABASE_URL")
	if databaseURL == "" {
		t.Skip("KOSCHEI_TEST_DATABASE_URL is not set")
	}
	db, err := sql.Open("postgres", databaseURL)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.SetMaxOpenConns(2)
	db.SetMaxIdleConns(1)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		t.Fatal(err)
	}

	suffix := fmt.Sprintf("%d", time.Now().UnixNano())
	programID := "CustomerLabProgram" + suffix
	bundleBytes, err := json.Marshal(map[string]string{
		"programs/customer/src/lib.rs": "pub fn transfer() { unsafe { invoke_unchecked(&ix, &accounts); } }",
	})
	if err != nil {
		t.Fatal(err)
	}
	input := ArtifactInput{
		ProgramID: programID, Network: "solana-mainnet", ArtifactType: "source_bundle",
		SourceURI: "private://customer-a/source", SourceCommit: "private-commit-a",
		ContentEncoding: "json", Content: string(bundleBytes),
		Metadata: map[string]any{"customer": "a"}, TrustLevel: "verified", Verified: true,
	}

	artifactA, err := StoreCustomerArtifact(ctx, db, input, "user:customer-a")
	if err != nil {
		t.Fatalf("store customer A artifact: %v", err)
	}
	input.SourceURI = "private://customer-b/source"
	input.SourceCommit = "private-commit-b"
	input.Metadata = map[string]any{"customer": "b"}
	artifactB, err := StoreCustomerArtifact(ctx, db, input, "user:customer-b")
	if err != nil {
		t.Fatalf("store customer B duplicate artifact: %v", err)
	}
	if artifactA.ArtifactRef != artifactB.ArtifactRef {
		t.Fatalf("content-addressed artifact refs differ: %s %s", artifactA.ArtifactRef, artifactB.ArtifactRef)
	}
	if artifactA.Verified || artifactA.TrustLevel != "unverified" {
		t.Fatalf("customer self-verification was not removed: %#v", artifactA)
	}

	for _, subject := range []string{"user:customer-a", "user:customer-b"} {
		if _, err := LoadCustomerArtifact(ctx, db, artifactA.ArtifactRef, subject); err != nil {
			t.Fatalf("subscriber %s cannot load artifact: %v", subject, err)
		}
		items, err := ListCustomerArtifacts(ctx, db, subject, programID, "solana-mainnet", 10)
		if err != nil || len(items) != 1 || items[0].ArtifactRef != artifactA.ArtifactRef {
			t.Fatalf("subscriber %s artifact list=%#v err=%v", subject, items, err)
		}
	}
	if _, err := LoadCustomerArtifact(ctx, db, artifactA.ArtifactRef, "user:customer-c"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("unsubscribed customer loaded artifact: %v", err)
	}

	resultA, err := AnalyzeCustomerArtifact(ctx, db, artifactA.ArtifactRef, "user:customer-a")
	if err != nil {
		t.Fatalf("analyze customer A: %v", err)
	}
	resultB, err := AnalyzeCustomerArtifact(ctx, db, artifactA.ArtifactRef, "user:customer-b")
	if err != nil {
		t.Fatalf("analyze customer B: %v", err)
	}
	if resultA.Summary.Decision != "block" || resultA.Summary.HighCount == 0 {
		t.Fatalf("expected high deterministic finding: %#v", resultA.Summary)
	}
	if resultA.Summary.RunRef == resultB.Summary.RunRef {
		t.Fatalf("customer run refs collided: %s", resultA.Summary.RunRef)
	}
	if resultA.Report.ReportHash == "" || resultA.Report.ReportHash != resultB.Report.ReportHash {
		t.Fatalf("same artifact produced nondeterministic report hashes: %s %s", resultA.Report.ReportHash, resultB.Report.ReportHash)
	}
	if resultA.VerdictAuthority || !resultA.StaticOnly {
		t.Fatalf("customer lab crossed authority boundary: %#v", resultA)
	}

	for _, subject := range []string{"user:customer-a", "user:customer-b"} {
		runs, err := ListCustomerLabRuns(ctx, db, subject, 10)
		if err != nil || len(runs) != 1 {
			t.Fatalf("subject %s runs=%#v err=%v", subject, runs, err)
		}
	}
	if runs, err := ListCustomerLabRuns(ctx, db, "user:customer-c", 10); err != nil || len(runs) != 0 {
		t.Fatalf("customer C saw runs=%#v err=%v", runs, err)
	}

	if _, err := db.ExecContext(ctx, `UPDATE defense_lab_runs SET decision='warn' WHERE run_ref=$1`, resultA.Summary.RunRef); err == nil || !strings.Contains(strings.ToLower(err.Error()), "immutable") {
		t.Fatalf("immutable run update was not blocked: %v", err)
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM defense_lab_runs WHERE run_ref=$1`, resultA.Summary.RunRef); err == nil || !strings.Contains(strings.ToLower(err.Error()), "immutable") {
		t.Fatalf("immutable run delete was not blocked: %v", err)
	}
}
