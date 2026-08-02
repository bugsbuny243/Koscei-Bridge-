package defense

import (
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestLatestWorkerImageAttestationPreventsStalePinReuse(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	workerID := "ci-image-rotation-" + time.Now().UTC().Format("150405.000000000")
	oldImage := "sha256:" + strings.Repeat("1", 64)
	newImage := "sha256:" + strings.Repeat("2", 64)
	toolName := "cargo"

	insertPinnedToolchainAttestationAt(t, ctx, db, workerID, oldImage, toolName, time.Now().UTC().Add(-time.Minute))
	insertPinnedToolchainAttestationAt(t, ctx, db, workerID, newImage, toolName, time.Now().UTC())

	latest, err := loadLatestPinnedToolAttestation(ctx, db, workerID, toolName)
	if err != nil {
		t.Fatal(err)
	}
	if latest.WorkerImageDigest != newImage {
		t.Fatalf("latest worker image was not selected: %+v", latest)
	}
	if latest.WorkerImageDigest == oldImage {
		t.Fatal("stale matching tool pin was reused after worker image rotation")
	}
}

func insertPinnedToolchainAttestationAt(t *testing.T, ctx context.Context, db *sql.DB, workerID, imageDigest, toolName string, observedAt time.Time) {
	t.Helper()
	version := toolName + " 1.0.0"
	versionHash := hashValue(version)
	binaryPath := "/usr/local/bin/" + toolName
	binaryHash := hashValue([]byte("binary:" + toolName + ":" + imageDigest))
	payload := map[string]any{
		"worker_id":           workerID,
		"worker_image_digest": imageDigest,
		"tool_name":           toolName,
		"command":             toolName + " --version",
		"available":           true,
		"version_hash":        versionHash,
		"binary_path":         binaryPath,
		"binary_hash":         binaryHash,
		"observed_at":         observedAt.Format(time.RFC3339Nano),
	}
	attestationRef := prefixedID("KTA1-", payload)
	attestationHash := hashJSON(payload)
	limitationsRaw, _ := json.Marshal([]string{})
	_, err := db.ExecContext(ctx, `INSERT INTO defense_toolchain_attestations
		(attestation_ref,worker_id,tool_name,command,available,version_output,version_hash,evidence_status,limitations,
		 attestation_hash,verdict_authority,observed_at,worker_image_digest,binary_path,binary_hash)
		VALUES($1,$2,$3,$4,true,$5,$6,'observed',$7::jsonb,$8,false,$9,$10,$11,$12)`,
		attestationRef, workerID, toolName, toolName+" --version", version, versionHash, string(limitationsRaw),
		attestationHash, observedAt, imageDigest, binaryPath, binaryHash)
	if err != nil {
		t.Fatal(err)
	}
}
