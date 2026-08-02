package defense

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"
)

func TestHarnessMaterializationIsDeterministicAndNonExecutable(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	profile := createMaterializationTestProfile(t, ctx, db, validLiteSVMCargoManifest(), validLiteSVMCargoLock(), "#[test]\r\nfn invariant() {\r\n    assert!(true);\r\n}")
	first, err := CreateHarnessMaterialization(ctx, db, HarnessMaterializationInput{ProfileRef: profile.ProfileRef})
	if err != nil {
		t.Fatal(err)
	}
	second, err := CreateHarnessMaterialization(ctx, db, HarnessMaterializationInput{ProfileRef: profile.ProfileRef})
	if err != nil {
		t.Fatal(err)
	}
	if first.MaterializationRef == "" || first.MaterializedArtifactRef == "" || first.MaterializationHash == "" {
		t.Fatalf("materialization identity is incomplete: %+v", first)
	}
	if first.MaterializationRef != second.MaterializationRef || first.MaterializedArtifactRef != second.MaterializedArtifactRef || first.MaterializedBundleHash != second.MaterializedBundleHash {
		t.Fatalf("identical evidence produced different materialization identities: first=%+v second=%+v", first, second)
	}
	if first.Status != "ready" || first.NetworkAccess || first.DependencyResolution || first.SourceExecuted || first.HarnessExecuted || first.MainnetTransactionSent || first.VerdictAuthority {
		t.Fatalf("materialization crossed a non-execution boundary: %+v", first)
	}
	if first.FileCount != 4 || len(first.FileManifest) != 4 {
		t.Fatalf("unexpected file manifest: %+v", first.FileManifest)
	}

	artifact, err := LoadArtifact(ctx, db, first.MaterializedArtifactRef)
	if err != nil {
		t.Fatal(err)
	}
	if artifact.ArtifactType != "source_bundle" || harnessArtifactMetadataString(artifact.Metadata, "artifact_role") != "materialized_harness" {
		t.Fatalf("unexpected materialized artifact: %+v", artifact)
	}
	bundle, err := decodeSourceBundle(artifact.Content)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := bundle[materializationManifestPath]; !ok {
		t.Fatal("generated materialization manifest is missing")
	}
	if strings.Contains(bundle["tests/invariant.rs"], "\r") || !strings.HasSuffix(bundle["tests/invariant.rs"], "\n") {
		t.Fatalf("test source was not normalized: %q", bundle["tests/invariant.rs"])
	}
	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM defense_harness_materializations WHERE materialization_ref=$1`, first.MaterializationRef).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("deterministic rematerialization created duplicate rows: %d", count)
	}
}

func TestNormalizeHarnessBundleRejectsMissingLockAndMutableDependencies(t *testing.T) {
	profile := HarnessExecutionProfile{ProfileRef: "KHEP1-0123456789abcdef0123456789abcdef", ProfileHash: "sha256:" + strings.Repeat("a", 64), ProgramID: "Demo1111111111111111111111111111111111111", Network: "solana-mainnet", Engine: HarnessEngineLiteSVM, CommandPolicy: harnessCommandPolicy(HarnessEngineLiteSVM)}
	source := Artifact{ArtifactRef: "KDA1-0123456789abcdef0123456789abcdef", ContentHash: "sha256:" + strings.Repeat("b", 64)}
	withoutLock := map[string]string{
		"Cargo.toml":         validLiteSVMCargoManifest(),
		"tests/invariant.rs": "#[test]\nfn invariant() {}\n",
	}
	if _, _, _, _, err := normalizeHarnessBundle(withoutLock, profile, source); err == nil || !strings.Contains(err.Error(), "Cargo.lock") {
		t.Fatalf("missing Cargo.lock was not rejected: %v", err)
	}
	gitManifest := strings.Replace(validLiteSVMCargoManifest(), `litesvm = "=0.6.1"`, `litesvm = { git = "https://example.invalid/litesvm" }`, 1)
	if err := validateOfflineCargoMaterialization(gitManifest, validLiteSVMCargoLock()); err == nil || !strings.Contains(err.Error(), "git dependencies") {
		t.Fatalf("git dependency was not rejected: %v", err)
	}
	pathManifest := validLiteSVMCargoManifest() + "\nhelper = { path = \"../outside\" }\n"
	if err := validateOfflineCargoMaterialization(pathManifest, validLiteSVMCargoLock()); err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("escaping path dependency was not rejected: %v", err)
	}
}

func TestHarnessMaterializationRejectsBlockedProfile(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	programID := fmt.Sprintf("CIBlockedMaterialization%d", time.Now().UnixNano())
	profile := createMaterializationProfileFixture(t, ctx, db, programID, validLiteSVMCargoManifest(), validLiteSVMCargoLock(), "#[test]\nfn invariant() {}\n", false)
	if profile.ReadinessStatus != "blocked" || profile.ExecutionAllowed {
		t.Fatalf("fixture did not create a blocked profile: %+v", profile)
	}
	if _, err := CreateHarnessMaterialization(ctx, db, HarnessMaterializationInput{ProfileRef: profile.ProfileRef}); err == nil || !strings.Contains(err.Error(), "blocked") {
		t.Fatalf("blocked profile was materialized: %v", err)
	}
}

func createMaterializationTestProfile(t *testing.T, ctx context.Context, db *sql.DB, cargoManifest, cargoLock, testSource string) HarnessExecutionProfile {
	t.Helper()
	programID := fmt.Sprintf("CIMaterialization%d", time.Now().UnixNano())
	return createMaterializationProfileFixture(t, ctx, db, programID, cargoManifest, cargoLock, testSource, true)
}

func createMaterializationProfileFixture(t *testing.T, ctx context.Context, db *sql.DB, programID, cargoManifest, cargoLock, testSource string, pinTools bool) HarnessExecutionProfile {
	t.Helper()
	targetRaw, _ := json.Marshal(map[string]string{
		"Cargo.toml": "[package]\nname='target-program'\nversion='0.1.0'\nedition='2021'\n",
		"src/lib.rs": "pub fn withdraw() {}\n",
	})
	target, err := StoreArtifact(ctx, db, ArtifactInput{
		ProgramID: programID, Network: "solana-mainnet", ArtifactType: "source_bundle", ContentEncoding: "json",
		Content: string(targetRaw), TrustLevel: "observed", CreatedBy: "ci",
	})
	if err != nil {
		t.Fatal(err)
	}
	idlRaw, _ := json.Marshal(map[string]any{
		"instructions": []any{map[string]any{
			"name":     "withdraw",
			"accounts": []any{map[string]any{"name": "authority", "signer": true}},
			"args":     []any{},
		}},
	})
	idl, err := StoreArtifact(ctx, db, ArtifactInput{
		ProgramID: programID, Network: "solana-mainnet", ArtifactType: "anchor_idl", ContentEncoding: "json",
		Content: string(idlRaw), Framework: "anchor", FrameworkVersion: "0.32.1", TrustLevel: "observed", CreatedBy: "ci",
	})
	if err != nil {
		t.Fatal(err)
	}
	plan, err := GenerateHarnessPlan(ctx, db, HarnessPlanInput{IDLArtifactRef: idl.ArtifactRef, SourceArtifactRef: target.ArtifactRef})
	if err != nil {
		t.Fatal(err)
	}
	harnessRaw, _ := json.Marshal(map[string]string{
		"Cargo.toml":         cargoManifest,
		"Cargo.lock":         cargoLock,
		"tests/invariant.rs": testSource,
	})
	harnessArtifact, err := StoreArtifact(ctx, db, ArtifactInput{
		ProgramID: programID, Network: "solana-mainnet", ArtifactType: "source_bundle", ContentEncoding: "json",
		Content: string(harnessRaw), TrustLevel: "observed", CreatedBy: "ci",
		Metadata: map[string]any{"artifact_role": "harness", "harness_plan_ref": plan.PlanRef},
	})
	if err != nil {
		t.Fatal(err)
	}
	workerID := fmt.Sprintf("ci-materialization-worker-%d", time.Now().UnixNano())
	imageDigest := "sha256:" + strings.Repeat("c", 64)
	if pinTools {
		for _, toolName := range []string{"cargo", "rustc"} {
			insertPinnedToolchainTestAttestation(t, ctx, db, workerID, imageDigest, toolName)
		}
	}
	profile, err := CreateHarnessExecutionProfile(ctx, db, HarnessExecutionProfileInput{
		PlanRef:             plan.PlanRef,
		HarnessArtifactRef:  harnessArtifact.ArtifactRef,
		Engine:              HarnessEngineLiteSVM,
		WorkerID:            workerID,
		WorkerImageDigest:   imageDigest,
		ConfirmedInvariants: []ConfirmedHarnessInvariant{{TemplateID: plan.InvariantTemplates[0].TemplateID, Statement: "Confirmed inputs must not panic."}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return profile
}

func validLiteSVMCargoManifest() string {
	return "[package]\r\nname = \"koschei-harness\"\r\nversion = \"0.1.0\"\r\nedition = \"2021\"\r\n\r\n[dev-dependencies]\r\nlitesvm = \"=0.6.1\""
}

func validLiteSVMCargoLock() string {
	return "version = 4\n\n[[package]]\nname = \"litesvm\"\nversion = \"0.6.1\"\n"
}
