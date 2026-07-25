package defense

import (
	"context"
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLiteSVMWorkerRequestRejectsInjectionAndDeduplicatesActiveJobs(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	profile := createMaterializationTestProfile(t, ctx, db, validLiteSVMCargoManifest(), validLiteSVMCargoLock(), "#[test]\nfn invariant() { assert!(true); }\n")
	materialization, err := CreateHarnessMaterialization(ctx, db, HarnessMaterializationInput{ProfileRef: profile.ProfileRef})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := EnqueueWorkerJob(ctx, db, WorkerJobRequest{
		Action: WorkerActionRunLiteSVMHarness, ProfileRef: profile.ProfileRef,
		MaterializationRef: materialization.MaterializationRef,
		Commands: []string{"cargo test --locked --offline; curl example.invalid"},
	}); err == nil || !strings.Contains(err.Error(), "only profile_ref and materialization_ref") {
		t.Fatalf("caller command injection was not rejected: %v", err)
	}

	first, err := EnqueueWorkerJob(ctx, db, WorkerJobRequest{
		Action: WorkerActionRunLiteSVMHarness, ProfileRef: profile.ProfileRef,
		MaterializationRef: materialization.MaterializationRef,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer finishLiteSVMTestJob(db, first.JobRef)
	second, err := EnqueueWorkerJob(ctx, db, WorkerJobRequest{
		Action: WorkerActionRunLiteSVMHarness, ProfileRef: profile.ProfileRef,
		MaterializationRef: materialization.MaterializationRef,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.JobRef == "" || first.JobRef != second.JobRef {
		t.Fatalf("duplicate active execution was not idempotent: first=%+v second=%+v", first, second)
	}
	if strings.Join(first.Commands, " ") != "cargo test --locked --offline" || len(first.Replacements) != 0 {
		t.Fatalf("worker job did not preserve the fixed no-replacement command contract: %+v", first)
	}
	var active int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM defense_worker_jobs WHERE action=$1 AND request_hash=$2 AND status IN ('queued','running')`, WorkerActionRunLiteSVMHarness, first.RequestHash).Scan(&active); err != nil {
		t.Fatal(err)
	}
	if active != 1 {
		t.Fatalf("expected one active LiteSVM job, got %d", active)
	}
}

func TestPrepareLiteSVMExecutionReauthorizesExactEvidence(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	profile := createMaterializationTestProfile(t, ctx, db, validLiteSVMCargoManifest(), validLiteSVMCargoLock(), "#[test]\nfn invariant() { assert!(true); }\n")
	bwrapPath := installPinnedBwrapTestAttestation(t, ctx, db, profile.WorkerID, profile.WorkerImageDigest)
	materialization, err := CreateHarnessMaterialization(ctx, db, HarnessMaterializationInput{ProfileRef: profile.ProfileRef})
	if err != nil {
		t.Fatal(err)
	}
	job, err := EnqueueWorkerJob(ctx, db, WorkerJobRequest{
		Action: WorkerActionRunLiteSVMHarness, ProfileRef: profile.ProfileRef,
		MaterializationRef: materialization.MaterializationRef,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer finishLiteSVMTestJob(db, job.JobRef)
	plan, err := PrepareLiteSVMExecution(ctx, db, job.JobRef, profile.ProfileRef, materialization.MaterializationRef, profile.WorkerID, profile.WorkerImageDigest)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(plan.CommandArgv, " ") != "cargo test --locked --offline" || plan.CommandHash == "" || plan.EnvironmentHash == "" || plan.InputHash == "" {
		t.Fatalf("prepared command evidence is incomplete: %+v", plan)
	}
	if plan.CargoExecutablePath == "" || plan.CargoExecutableHash == "" || plan.SandboxExecutablePath != bwrapPath ||
		plan.SandboxExecutableHash == "" || plan.SandboxPolicyHash == "" || len(plan.ExecutableEvidence) != 3 ||
		len(plan.Bundle) != materialization.FileCount {
		t.Fatalf("prepared executable/materialization evidence is incomplete: %+v", plan)
	}
	if plan.EnvironmentTemplate["CARGO_NET_OFFLINE"] != "true" ||
		plan.EnvironmentTemplate["CARGO_TARGET_DIR"] != "/tmp/koschei-scratch/target" ||
		plan.EnvironmentTemplate["RUSTC"] == "" || plan.SandboxPolicy["unshare_all"] != true ||
		plan.SandboxPolicy["host_work_root_masked"] != true || plan.SandboxPolicy["shell"] != false {
		t.Fatalf("prepared sandbox/environment policy is incomplete: env=%+v sandbox=%+v", plan.EnvironmentTemplate, plan.SandboxPolicy)
	}
	if plan.NetworkAccess || plan.DependencyResolution || plan.WalletMaterialAccessed || plan.MainnetRPCAccessed || plan.MainnetTransactionSent || plan.VerdictAuthority {
		t.Fatalf("prepared plan crossed a Phase 12C boundary: %+v", plan)
	}
	if _, err := PrepareLiteSVMExecution(ctx, db, job.JobRef, profile.ProfileRef, materialization.MaterializationRef, profile.WorkerID, "sha256:"+strings.Repeat("f", 64)); err == nil {
		t.Fatal("mismatched live worker image was authorized")
	}
	if err := os.WriteFile(bwrapPath, []byte("#!/bin/sh\necho mutated\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := PrepareLiteSVMExecution(ctx, db, job.JobRef, profile.ProfileRef, materialization.MaterializationRef, profile.WorkerID, profile.WorkerImageDigest); err == nil || !strings.Contains(strings.ToLower(err.Error()), "bubblewrap executable hash changed") {
		t.Fatalf("mutated sandbox launcher was authorized: %v", err)
	}
}

func TestLiteSVMExecutionAttemptIsImmutableAndResultHashIsRepeatable(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	defer cancel()

	profile := createMaterializationTestProfile(t, ctx, db, validLiteSVMCargoManifest(), validLiteSVMCargoLock(), "#[test]\nfn invariant() { assert!(true); }\n")
	installPinnedBwrapTestAttestation(t, ctx, db, profile.WorkerID, profile.WorkerImageDigest)
	materialization, err := CreateHarnessMaterialization(ctx, db, HarnessMaterializationInput{ProfileRef: profile.ProfileRef})
	if err != nil {
		t.Fatal(err)
	}
	firstJob, err := EnqueueWorkerJob(ctx, db, WorkerJobRequest{Action: WorkerActionRunLiteSVMHarness, ProfileRef: profile.ProfileRef, MaterializationRef: materialization.MaterializationRef})
	if err != nil {
		t.Fatal(err)
	}
	defer finishLiteSVMTestJob(db, firstJob.JobRef)
	firstPlan, err := PrepareLiteSVMExecution(ctx, db, firstJob.JobRef, profile.ProfileRef, materialization.MaterializationRef, profile.WorkerID, profile.WorkerImageDigest)
	if err != nil {
		t.Fatal(err)
	}
	exitCode := 0
	firstStarted := time.Now().UTC().Add(-2 * time.Second)
	first, err := PersistLiteSVMExecutionAttempt(ctx, db, firstPlan, LiteSVMExecutionOutcome{
		AttemptNumber: 1, Status: "completed", StartedAt: firstStarted, CompletedAt: firstStarted.Add(time.Second),
		ExitCode: &exitCode, TerminationReason: "process_exited", Stdout: "test result: ok\n", Stderr: "",
		SourceExecuted: true, HarnessExecuted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.AttemptRef == "" || first.ResultHash == "" || first.SandboxPolicyHash == "" ||
		first.NetworkAccess || first.DependencyResolution || first.WalletMaterialAccessed || first.MainnetRPCAccessed ||
		first.MainnetTransactionSent || first.VerdictAuthority {
		t.Fatalf("persisted attempt crossed an execution boundary: %+v", first)
	}
	if _, err := db.ExecContext(ctx, `UPDATE defense_litesvm_execution_attempts SET status='failed' WHERE attempt_ref=$1`, first.AttemptRef); err == nil {
		t.Fatal("immutable LiteSVM attempt accepted an update")
	}

	if _, err := db.ExecContext(ctx, `UPDATE defense_worker_jobs SET status='completed',completed_at=now(),updated_at=now() WHERE job_ref=$1`, firstJob.JobRef); err != nil {
		t.Fatal(err)
	}
	secondJob, err := EnqueueWorkerJob(ctx, db, WorkerJobRequest{Action: WorkerActionRunLiteSVMHarness, ProfileRef: profile.ProfileRef, MaterializationRef: materialization.MaterializationRef})
	if err != nil {
		t.Fatal(err)
	}
	defer finishLiteSVMTestJob(db, secondJob.JobRef)
	if secondJob.JobRef == firstJob.JobRef {
		t.Fatal("terminal execution did not permit a deliberate later rerun")
	}
	secondPlan, err := PrepareLiteSVMExecution(ctx, db, secondJob.JobRef, profile.ProfileRef, materialization.MaterializationRef, profile.WorkerID, profile.WorkerImageDigest)
	if err != nil {
		t.Fatal(err)
	}
	secondStarted := firstStarted.Add(10 * time.Minute)
	second, err := PersistLiteSVMExecutionAttempt(ctx, db, secondPlan, LiteSVMExecutionOutcome{
		AttemptNumber: 1, Status: "completed", StartedAt: secondStarted, CompletedAt: secondStarted.Add(3 * time.Second),
		ExitCode: &exitCode, TerminationReason: "process_exited", Stdout: "test result: ok\n", Stderr: "",
		SourceExecuted: true, HarnessExecuted: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if first.AttemptRef == second.AttemptRef || first.ResultHash != second.ResultHash {
		t.Fatalf("repeat execution identity/hash contract failed: first=%+v second=%+v", first, second)
	}
}

func TestBoundLiteSVMOutputIsUTF8SafeAndDeterministic(t *testing.T) {
	input := strings.Repeat("a", 15) + "€" + strings.Repeat("b", 20)
	first, truncated := boundLiteSVMOutput(input, 16)
	second, secondTruncated := boundLiteSVMOutput(input, 16)
	if !truncated || !secondTruncated || first != second || !strings.HasPrefix(input, first) || len(first) > 16 {
		t.Fatalf("unexpected bounded output: first=%q second=%q", first, second)
	}
}

func installPinnedBwrapTestAttestation(t *testing.T, ctx context.Context, db *sql.DB, workerID, imageDigest string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "bwrap")
	content := []byte("#!/bin/sh\necho 'bubblewrap 1.0.0'\n")
	if err := os.WriteFile(path, content, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	binaryHash, err := hashDefenseExecutable(path)
	if err != nil {
		t.Fatal(err)
	}
	observedAt := time.Now().UTC()
	version := "bubblewrap 1.0.0"
	versionHash := hashValue(version)
	payload := map[string]any{
		"worker_id": workerID,
		"worker_image_digest": imageDigest,
		"tool_name": "bwrap",
		"command": "bwrap --version",
		"available": true,
		"version_hash": versionHash,
		"binary_path": path,
		"binary_hash": binaryHash,
		"observed_at": observedAt.Format(time.RFC3339Nano),
	}
	attestationRef := prefixedID("KTA1-", payload)
	limitationsRaw, _ := json.Marshal([]string{})
	_, err = db.ExecContext(ctx, `INSERT INTO defense_toolchain_attestations
		(attestation_ref,worker_id,tool_name,command,available,version_output,version_hash,evidence_status,limitations,
		 attestation_hash,verdict_authority,observed_at,worker_image_digest,binary_path,binary_hash)
		VALUES($1,$2,'bwrap','bwrap --version',true,$3,$4,'observed',$5::jsonb,$6,false,$7,$8,$9,$10)`,
		attestationRef, workerID, version, versionHash, string(limitationsRaw), hashJSON(payload), observedAt,
		imageDigest, path, binaryHash)
	if err != nil {
		t.Fatal(err)
	}
	return path
}

func finishLiteSVMTestJob(db *sql.DB, jobRef string) {
	if db == nil || strings.TrimSpace(jobRef) == "" {
		return
	}
	_, _ = db.Exec(`UPDATE defense_worker_jobs SET status='completed',completed_at=COALESCE(completed_at,now()),lease_expires_at=NULL,updated_at=now() WHERE job_ref=$1 AND status IN ('queued','running')`, jobRef)
}
