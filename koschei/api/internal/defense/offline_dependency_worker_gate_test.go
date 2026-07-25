package defense

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestExecuteLiteSVMWorkerJobRejectsMissingOfflineInventoryBeforeSourceLaunch(t *testing.T) {
	if _, err := os.Stat(OfflineDependencyRootPath); err == nil {
		t.Skip("host already contains the production offline dependency root")
	}
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
	job, err := EnqueueWorkerJob(ctx, db, WorkerJobRequest{Action: WorkerActionRunLiteSVMHarness, ProfileRef: profile.ProfileRef, MaterializationRef: materialization.MaterializationRef})
	if err != nil {
		t.Fatal(err)
	}
	defer finishLiteSVMTestJob(db, job.JobRef)
	job.Attempts = 1
	workRoot := offlineDependencyWorkerTestRoot(t)

	attempt, err := ExecuteLiteSVMWorkerJob(ctx, db, job, LiteSVMWorkerRuntime{
		WorkerID:                profile.WorkerID,
		WorkerImageDigest:       profile.WorkerImageDigest,
		WorkRoot:                workRoot,
		WorkerEnabled:           true,
		SandboxEnabled:          true,
		HarnessExecutionEnabled: true,
		LiteSVMExecutionEnabled: true,
		NetworkIsolated:         true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if attempt.Status != "rejected" || attempt.TerminationReason != DependencyInventoryUnavailable || attempt.SourceExecuted || attempt.HarnessExecuted || attempt.NetworkAccess || attempt.DependencyResolution || attempt.VerdictAuthority {
		t.Fatalf("missing inventory did not fail closed before source launch: %+v", attempt)
	}
	if len(attempt.Limitations) == 0 || !strings.Contains(attempt.Limitations[0], DependencyInventoryUnavailable) {
		t.Fatalf("dependency rejection evidence is missing: %+v", attempt.Limitations)
	}
}

func offlineDependencyWorkerTestRoot(t *testing.T) string {
	t.Helper()
	base := strings.TrimSpace(os.Getenv("RUNNER_TOOL_CACHE"))
	if base == "" {
		base = "/opt/hostedtoolcache"
	}
	root, err := os.MkdirTemp(base, "koschei-dependency-worker-")
	if err != nil {
		t.Skipf("no writable non-masked worker test root: %v", err)
	}
	root, err = filepath.Abs(root)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(root, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	return root
}
