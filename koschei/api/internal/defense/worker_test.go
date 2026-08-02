package defense

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	_ "github.com/lib/pq"
)

func defenseWorkerTestDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("postgres", "postgres://postgres:postgres@127.0.0.1:5432/koschei_ci?sslmode=disable")
	if err != nil {
		t.Skipf("postgres unavailable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := db.PingContext(ctx); err != nil {
		db.Close()
		t.Skipf("postgres unavailable: %v", err)
	}
	return db
}

func TestDefenseWorkerQueueLifecycle(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	programID := fmt.Sprintf("CIWorkerProgram%d", time.Now().UnixNano())
	bundle, _ := json.Marshal(map[string]string{
		"Cargo.toml": "[package]\nname='ci-worker'\nversion='0.1.0'\nedition='2021'\n",
		"src/lib.rs": "pub fn ok() -> bool { true }\n",
	})
	artifact, err := StoreArtifact(ctx, db, ArtifactInput{
		ProgramID:       programID,
		Network:         "solana-mainnet",
		ArtifactType:    "source_bundle",
		ContentEncoding: "json",
		Content:         string(bundle),
		TrustLevel:      "observed",
		CreatedBy:       "ci",
	})
	if err != nil {
		t.Fatal(err)
	}
	job, err := EnqueueWorkerJob(ctx, db, WorkerJobRequest{
		Action:            WorkerActionVerifyBundle,
		SourceArtifactRef: artifact.ArtifactRef,
		Commands:          []string{"cargo test"},
		MaxAttempts:       2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if job.Status != "queued" || job.JobRef == "" || job.RequestHash == "" {
		t.Fatalf("unexpected queued job: %+v", job)
	}
	claimed, ok, err := ClaimWorkerJob(ctx, db, "ci-defense-worker", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || claimed.JobRef != job.JobRef || claimed.Status != "running" || claimed.Attempts != 1 {
		t.Fatalf("unexpected claimed job: ok=%v job=%+v", ok, claimed)
	}
	result := map[string]any{"verification_ref": "ci", "verdict_authority": false}
	if err := CompleteWorkerJob(ctx, db, claimed, "ci-defense-worker", result); err != nil {
		t.Fatal(err)
	}
	stored, err := GetWorkerJob(ctx, db, job.JobRef)
	if err != nil {
		t.Fatal(err)
	}
	if stored.Status != "completed" || stored.Progress != 100 || stored.ResultHash == "" {
		t.Fatalf("unexpected completed job: %+v", stored)
	}
	var eventCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM defense_worker_job_events WHERE job_ref=$1`, job.JobRef).Scan(&eventCount); err != nil {
		t.Fatal(err)
	}
	if eventCount != 3 {
		t.Fatalf("expected queued, claimed and completed events, got %d", eventCount)
	}
}

func TestDefenseWorkerRejectsUnallowlistedCommand(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	programID := fmt.Sprintf("CIWorkerReject%d", time.Now().UnixNano())
	bundle, _ := json.Marshal(map[string]string{"src/lib.rs": "pub fn ok() {}\n"})
	artifact, err := StoreArtifact(ctx, db, ArtifactInput{
		ProgramID:       programID,
		Network:         "solana-mainnet",
		ArtifactType:    "source_bundle",
		ContentEncoding: "json",
		Content:         string(bundle),
		TrustLevel:      "observed",
		CreatedBy:       "ci",
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = EnqueueWorkerJob(ctx, db, WorkerJobRequest{
		Action:            WorkerActionVerifyBundle,
		SourceArtifactRef: artifact.ArtifactRef,
		Commands:          []string{"sh -c whoami"},
	})
	if err == nil {
		t.Fatal("unallowlisted shell command was accepted")
	}
}
