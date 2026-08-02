package defense

import (
	"context"
	"encoding/json"
	"fmt"
	"testing"
	"time"
)

func TestVersionedReproductionPairCreatesVerifiedProof(t *testing.T) {
	db := defenseWorkerTestDB(t)
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	programID := fmt.Sprintf("CIReproduction%d", time.Now().UnixNano())
	bundle, _ := json.Marshal(map[string]string{
		"Cargo.toml": "[package]\nname='ci-repro'\nversion='0.1.0'\nedition='2021'\n",
		"src/lib.rs": "use anchor_lang::prelude::*;\npub struct Demo<'info>{ pub target: UncheckedAccount<'info> }\n",
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
	report, err := AnalyzeArtifact(artifact)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Findings) == 0 {
		t.Fatal("expected static finding")
	}
	if err := PersistLabReport(ctx, db, report); err != nil {
		t.Fatal(err)
	}
	finding := report.Findings[0]

	patchPayload := map[string]any{
		"summary":     "CI defensive patch",
		"files":       []map[string]any{{"path": "src/lib.rs", "content": "pub fn patched() {}\n", "reason": "CI"}},
		"tests":       []string{"cargo test"},
		"limitations": []string{},
	}
	patchRaw, _ := json.Marshal(patchPayload)
	patchHash := hashValue(patchRaw)
	patchRef := prefixedID("KDP1-", map[string]any{"program": programID, "finding": finding.FindingRef, "nonce": time.Now().UnixNano()})
	_, err = db.ExecContext(ctx, `INSERT INTO defense_patch_proposals
		(patch_ref,program_id,network,finding_ref,source_artifact_ref,provider,model,proposal_json,proposal_hash,human_approved,applied_to_production,created_by)
		VALUES($1,$2,'solana-mainnet',$3,$4,'ci','ci',$5::jsonb,$6,false,false,'ci')`, patchRef, programID, finding.FindingRef, artifact.ArtifactRef, string(patchRaw), patchHash)
	if err != nil {
		t.Fatal(err)
	}
	approvalPayload := map[string]any{"patch_ref": patchRef, "reason": "CI approval"}
	approvalHash := hashJSON(approvalPayload)
	approvalRef := prefixedID("KPA1-", approvalPayload)
	_, err = db.ExecContext(ctx, `INSERT INTO defense_patch_approvals(approval_ref,patch_ref,approved_by,approval_reason,approval_hash)
		VALUES($1,$2,'ci','CI approval',$3)`, approvalRef, patchRef, approvalHash)
	if err != nil {
		t.Fatal(err)
	}

	invariant, err := CreateReproductionInvariant(ctx, db, ReproductionInvariantInput{
		FindingRef:        finding.FindingRef,
		SourceArtifactRef: artifact.ArtifactRef,
		InvariantVersion:  "v1.0.0",
		Command:           "cargo test",
		BaselineMarker:    "KOSCHEI_BASELINE_EXPLOIT_REPRODUCED",
		PatchedMarker:     "KOSCHEI_PATCHED_EXPLOIT_PATH_BLOCKED",
		Rationale:         "CI proves that only a paired, marker-bound run may verify the patch.",
	})
	if err != nil {
		t.Fatal(err)
	}
	pair, err := PrepareReproductionPair(ctx, db, invariant.InvariantRef, patchRef)
	if err != nil {
		t.Fatal(err)
	}

	baselineClaim, ok, err := ClaimWorkerJob(ctx, db, "ci-repro-worker", time.Minute)
	if err != nil || !ok || baselineClaim.JobRef != pair.BaselineJob.JobRef {
		t.Fatalf("unexpected baseline claim: ok=%v err=%v job=%+v", ok, err, baselineClaim)
	}
	baselineReport := finishVerification(VerificationReport{
		ProgramID: programID, Network: "solana-mainnet", FindingRef: finding.FindingRef,
		SourceArtifactRef: artifact.ArtifactRef, ExecutionMode: "local_sandbox", Status: "passed",
		Commands: []string{"cargo test"}, Results: []CommandResult{{Command: "cargo test", Status: "passed", ExitCode: 0, Output: "ok KOSCHEI_BASELINE_EXPLOIT_REPRODUCED"}},
		InputHash: hashValue("baseline"), Limitations: []string{}, CanExecuteMainnet: false,
	})
	if err := PersistVerification(ctx, db, baselineReport); err != nil {
		t.Fatal(err)
	}
	if err := CompleteWorkerJob(ctx, db, baselineClaim, "ci-repro-worker", map[string]any{"verification": baselineReport}); err != nil {
		t.Fatal(err)
	}

	patchedClaim, ok, err := ClaimWorkerJob(ctx, db, "ci-repro-worker", time.Minute)
	if err != nil || !ok || patchedClaim.JobRef != pair.PatchedJob.JobRef {
		t.Fatalf("unexpected patched claim: ok=%v err=%v job=%+v", ok, err, patchedClaim)
	}
	patchedReport := finishVerification(VerificationReport{
		ProgramID: programID, Network: "solana-mainnet", FindingRef: finding.FindingRef,
		SourceArtifactRef: artifact.ArtifactRef, PatchRef: patchRef, ExecutionMode: "local_sandbox", Status: "passed",
		Commands: []string{"cargo test"}, Results: []CommandResult{{Command: "cargo test", Status: "passed", ExitCode: 0, Output: "ok KOSCHEI_PATCHED_EXPLOIT_PATH_BLOCKED"}},
		InputHash: hashValue("patched"), Limitations: []string{}, CanExecuteMainnet: false,
	})
	if err := PersistVerification(ctx, db, patchedReport); err != nil {
		t.Fatal(err)
	}
	if err := CompleteWorkerJob(ctx, db, patchedClaim, "ci-repro-worker", map[string]any{"verification": patchedReport}); err != nil {
		t.Fatal(err)
	}

	run, err := FinalizeReproductionPair(ctx, db, invariant.InvariantRef, patchRef, pair.BaselineJob.JobRef, pair.PatchedJob.JobRef)
	if err != nil {
		t.Fatal(err)
	}
	if run.Status != "verified" || run.ProofRef == "" || !run.BaselineMarkerObserved || !run.PatchedMarkerObserved {
		t.Fatalf("unexpected reproduction run: %+v", run)
	}
	var proofStatus string
	if err := db.QueryRowContext(ctx, `SELECT status FROM defense_proof_of_fix WHERE proof_ref=$1`, run.ProofRef).Scan(&proofStatus); err != nil {
		t.Fatal(err)
	}
	if proofStatus != "verified" {
		t.Fatalf("unexpected proof status: %s", proofStatus)
	}
}

func TestValidateReproductionMarkerOutput(t *testing.T) {
	if err := ValidateReproductionMarkerOutput("log KOSCHEI_BASELINE_EXPLOIT_REPRODUCED done", "KOSCHEI_BASELINE_EXPLOIT_REPRODUCED"); err != nil {
		t.Fatal(err)
	}
	if err := ValidateReproductionMarkerOutput("ordinary test passed", "KOSCHEI_BASELINE_EXPLOIT_REPRODUCED"); err == nil {
		t.Fatal("ordinary test output was accepted as reproduction evidence")
	}
	if err := ValidateReproductionMarkerOutput("anything", "bad marker"); err == nil {
		t.Fatal("invalid marker format was accepted")
	}
}
