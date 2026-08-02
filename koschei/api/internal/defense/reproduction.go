package defense

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

var reproductionMarkerPattern = regexp.MustCompile(`^KOSCHEI_[A-Z0-9_:-]{8,120}$`)
var invariantVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+$`)

type ReproductionInvariantInput struct {
	FindingRef        string `json:"finding_ref"`
	SourceArtifactRef string `json:"source_artifact_ref"`
	InvariantVersion  string `json:"invariant_version"`
	Command           string `json:"command"`
	BaselineMarker    string `json:"baseline_marker"`
	PatchedMarker     string `json:"patched_marker"`
	Rationale         string `json:"rationale"`
}

type ReproductionInvariant struct {
	InvariantRef      string    `json:"invariant_ref"`
	InvariantVersion  string    `json:"invariant_version"`
	ProgramID         string    `json:"program_id"`
	Network           string    `json:"network"`
	FindingRef        string    `json:"finding_ref"`
	SourceArtifactRef string    `json:"source_artifact_ref"`
	Command           string    `json:"command"`
	BaselineMarker    string    `json:"baseline_marker"`
	PatchedMarker     string    `json:"patched_marker"`
	Rationale         string    `json:"rationale"`
	ApprovedBy        string    `json:"approved_by"`
	ApprovalHash      string    `json:"approval_hash"`
	Active            bool      `json:"active"`
	VerdictAuthority  bool      `json:"verdict_authority"`
	CreatedAt         time.Time `json:"created_at"`
}

type ReproductionPair struct {
	Invariant   ReproductionInvariant `json:"invariant"`
	PatchRef    string                `json:"patch_ref"`
	BaselineJob WorkerJob             `json:"baseline_job"`
	PatchedJob  WorkerJob             `json:"patched_job"`
}

type ReproductionRun struct {
	RunRef                  string    `json:"run_ref"`
	InvariantRef            string    `json:"invariant_ref"`
	ProgramID               string    `json:"program_id"`
	Network                 string    `json:"network"`
	FindingRef              string    `json:"finding_ref"`
	PatchRef                string    `json:"patch_ref"`
	BaselineJobRef          string    `json:"baseline_job_ref"`
	PatchedJobRef           string    `json:"patched_job_ref"`
	BaselineVerificationRef string    `json:"baseline_verification_ref"`
	PatchedVerificationRef  string    `json:"patched_verification_ref"`
	BaselineMarkerObserved  bool      `json:"baseline_marker_observed"`
	PatchedMarkerObserved   bool      `json:"patched_marker_observed"`
	Status                  string    `json:"status"`
	EvidenceRefs            []string  `json:"evidence_refs"`
	Limitations             []string  `json:"limitations"`
	RunHash                 string    `json:"run_hash"`
	ProofRef                string    `json:"proof_ref,omitempty"`
	VerdictAuthority        bool      `json:"verdict_authority"`
	CreatedAt               time.Time `json:"created_at"`
}

type storedVerification struct {
	VerificationRef   string
	ProgramID         string
	Network           string
	FindingRef        string
	SourceArtifactRef string
	PatchRef          string
	Status            string
	Commands          []string
	Results           []CommandResult
}

type storedPatchProposal struct {
	Files []struct {
		Path    string `json:"path"`
		Content string `json:"content"`
	} `json:"files"`
}

func CreateReproductionInvariant(ctx context.Context, db *sql.DB, input ReproductionInvariantInput) (ReproductionInvariant, error) {
	if db == nil {
		return ReproductionInvariant{}, errors.New("database unavailable")
	}
	input.FindingRef = strings.TrimSpace(input.FindingRef)
	input.SourceArtifactRef = strings.TrimSpace(input.SourceArtifactRef)
	input.InvariantVersion = strings.TrimSpace(input.InvariantVersion)
	input.Command = strings.Join(strings.Fields(input.Command), " ")
	input.BaselineMarker = strings.TrimSpace(input.BaselineMarker)
	input.PatchedMarker = strings.TrimSpace(input.PatchedMarker)
	input.Rationale = strings.TrimSpace(input.Rationale)
	if input.FindingRef == "" || input.SourceArtifactRef == "" || input.Rationale == "" {
		return ReproductionInvariant{}, errors.New("finding, source artifact and rationale are required")
	}
	if !invariantVersionPattern.MatchString(input.InvariantVersion) {
		return ReproductionInvariant{}, errors.New("invariant_version must use vMAJOR.MINOR.PATCH")
	}
	if _, ok := allowedCommand(input.Command); !ok {
		return ReproductionInvariant{}, errors.New("invariant command is not allowlisted")
	}
	if !reproductionMarkerPattern.MatchString(input.BaselineMarker) || !reproductionMarkerPattern.MatchString(input.PatchedMarker) || input.BaselineMarker == input.PatchedMarker {
		return ReproductionInvariant{}, errors.New("invariant markers are invalid or identical")
	}
	var programID, network, findingArtifact string
	if err := db.QueryRowContext(ctx, `SELECT program_id,network,COALESCE(source_artifact_ref,'') FROM defense_program_findings WHERE finding_ref=$1`, input.FindingRef).Scan(&programID, &network, &findingArtifact); err != nil {
		return ReproductionInvariant{}, errors.New("finding not found")
	}
	artifact, err := LoadArtifact(ctx, db, input.SourceArtifactRef)
	if err != nil {
		return ReproductionInvariant{}, err
	}
	if artifact.ProgramID != programID || artifact.Network != network || (findingArtifact != "" && findingArtifact != artifact.ArtifactRef) {
		return ReproductionInvariant{}, errors.New("invariant source artifact does not match the finding")
	}
	payload := map[string]any{
		"finding_ref":         input.FindingRef,
		"source_artifact_ref": artifact.ArtifactRef,
		"version":             input.InvariantVersion,
		"command":             input.Command,
		"baseline_marker":     input.BaselineMarker,
		"patched_marker":      input.PatchedMarker,
		"rationale":           input.Rationale,
		"approved_by":         "owner",
	}
	approvalHash := hashJSON(payload)
	ref := prefixedID("KRI1-", payload)
	now := time.Now().UTC()
	_, err = db.ExecContext(ctx, `INSERT INTO defense_reproduction_invariants
		(invariant_ref,invariant_version,program_id,network,finding_ref,source_artifact_ref,command,baseline_marker,patched_marker,rationale,approved_by,approval_hash,active,verdict_authority,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,'owner',$11,true,false,$12) ON CONFLICT(invariant_ref) DO NOTHING`,
		ref, input.InvariantVersion, programID, network, input.FindingRef, artifact.ArtifactRef, input.Command,
		input.BaselineMarker, input.PatchedMarker, input.Rationale, approvalHash, now)
	if err != nil {
		return ReproductionInvariant{}, err
	}
	return ReproductionInvariant{InvariantRef: ref, InvariantVersion: input.InvariantVersion, ProgramID: programID, Network: network,
		FindingRef: input.FindingRef, SourceArtifactRef: artifact.ArtifactRef, Command: input.Command, BaselineMarker: input.BaselineMarker,
		PatchedMarker: input.PatchedMarker, Rationale: input.Rationale, ApprovedBy: "owner", ApprovalHash: approvalHash,
		Active: true, VerdictAuthority: false, CreatedAt: now}, nil
}

func GetReproductionInvariant(ctx context.Context, db *sql.DB, ref string) (ReproductionInvariant, error) {
	var item ReproductionInvariant
	err := db.QueryRowContext(ctx, `SELECT invariant_ref,invariant_version,program_id,network,finding_ref,source_artifact_ref,command,
		baseline_marker,patched_marker,rationale,approved_by,approval_hash,active,verdict_authority,created_at
		FROM defense_reproduction_invariants WHERE invariant_ref=$1`, strings.TrimSpace(ref)).Scan(
		&item.InvariantRef, &item.InvariantVersion, &item.ProgramID, &item.Network, &item.FindingRef, &item.SourceArtifactRef,
		&item.Command, &item.BaselineMarker, &item.PatchedMarker, &item.Rationale, &item.ApprovedBy, &item.ApprovalHash,
		&item.Active, &item.VerdictAuthority, &item.CreatedAt)
	return item, err
}

func PrepareReproductionPair(ctx context.Context, db *sql.DB, invariantRef, patchRef string) (ReproductionPair, error) {
	invariant, err := GetReproductionInvariant(ctx, db, invariantRef)
	if err != nil || !invariant.Active {
		return ReproductionPair{}, errors.New("active reproduction invariant not found")
	}
	patchRef = strings.TrimSpace(patchRef)
	var sourceArtifactRef, findingRef string
	var proposalRaw []byte
	var approved bool
	if err := db.QueryRowContext(ctx, `SELECT p.source_artifact_ref,COALESCE(p.finding_ref,''),p.proposal_json,
		EXISTS(SELECT 1 FROM defense_patch_approvals a WHERE a.patch_ref=p.patch_ref)
		FROM defense_patch_proposals p WHERE p.patch_ref=$1`, patchRef).Scan(&sourceArtifactRef, &findingRef, &proposalRaw, &approved); err != nil {
		return ReproductionPair{}, errors.New("patch proposal not found")
	}
	if !approved {
		return ReproductionPair{}, errors.New("patch proposal requires immutable owner approval")
	}
	if sourceArtifactRef != invariant.SourceArtifactRef || findingRef != invariant.FindingRef {
		return ReproductionPair{}, errors.New("patch proposal is not bound to the reproduction invariant")
	}
	var proposal storedPatchProposal
	if err := json.Unmarshal(proposalRaw, &proposal); err != nil || len(proposal.Files) == 0 || len(proposal.Files) > 20 {
		return ReproductionPair{}, errors.New("patch proposal content is invalid")
	}
	replacements := map[string]string{}
	for _, file := range proposal.Files {
		clean, err := safeRelativePath(file.Path)
		if err != nil || len(file.Content) > 300000 {
			return ReproductionPair{}, errors.New("patch proposal contains an unsafe replacement")
		}
		replacements[clean] = file.Content
	}
	baseline, err := EnqueueWorkerJob(ctx, db, WorkerJobRequest{
		Action:            WorkerActionVerifyBundle,
		SourceArtifactRef: invariant.SourceArtifactRef,
		FindingRef:        invariant.FindingRef,
		Commands:          []string{invariant.Command},
		MaxAttempts:       2,
	})
	if err != nil {
		return ReproductionPair{}, err
	}
	patched, err := EnqueueWorkerJob(ctx, db, WorkerJobRequest{
		Action:            WorkerActionVerifyBundle,
		SourceArtifactRef: invariant.SourceArtifactRef,
		FindingRef:        invariant.FindingRef,
		PatchRef:          patchRef,
		Commands:          []string{invariant.Command},
		Replacements:      replacements,
		MaxAttempts:       2,
	})
	if err != nil {
		return ReproductionPair{}, err
	}
	return ReproductionPair{Invariant: invariant, PatchRef: patchRef, BaselineJob: baseline, PatchedJob: patched}, nil
}

func FinalizeReproductionPair(ctx context.Context, db *sql.DB, invariantRef, patchRef, baselineJobRef, patchedJobRef string) (ReproductionRun, error) {
	invariant, err := GetReproductionInvariant(ctx, db, invariantRef)
	if err != nil {
		return ReproductionRun{}, errors.New("reproduction invariant not found")
	}
	baselineJob, err := GetWorkerJob(ctx, db, baselineJobRef)
	if err != nil {
		return ReproductionRun{}, errors.New("baseline worker job not found")
	}
	patchedJob, err := GetWorkerJob(ctx, db, patchedJobRef)
	if err != nil {
		return ReproductionRun{}, errors.New("patched worker job not found")
	}
	if baselineJob.Status != "completed" || patchedJob.Status != "completed" {
		return ReproductionRun{}, errors.New("both reproduction worker jobs must be completed")
	}
	if baselineJob.SourceArtifactRef != invariant.SourceArtifactRef || patchedJob.SourceArtifactRef != invariant.SourceArtifactRef ||
		baselineJob.FindingRef != invariant.FindingRef || patchedJob.FindingRef != invariant.FindingRef || baselineJob.PatchRef != "" || patchedJob.PatchRef != strings.TrimSpace(patchRef) {
		return ReproductionRun{}, errors.New("worker jobs are not bound to the invariant and patch")
	}
	baselineRef, err := workerVerificationRef(baselineJob)
	if err != nil {
		return ReproductionRun{}, err
	}
	patchedRef, err := workerVerificationRef(patchedJob)
	if err != nil {
		return ReproductionRun{}, err
	}
	baseline, err := loadStoredVerification(ctx, db, baselineRef)
	if err != nil {
		return ReproductionRun{}, err
	}
	patched, err := loadStoredVerification(ctx, db, patchedRef)
	if err != nil {
		return ReproductionRun{}, err
	}
	if !verificationBoundToInvariant(baseline, invariant, "") || !verificationBoundToInvariant(patched, invariant, strings.TrimSpace(patchRef)) {
		return ReproductionRun{}, errors.New("immutable verification records are not bound to the invariant")
	}
	baselineMarkerObserved := verificationContainsMarker(baseline, invariant.BaselineMarker)
	patchedMarkerObserved := verificationContainsMarker(patched, invariant.PatchedMarker)
	status := "verified"
	limitations := []string{}
	if baseline.Status != "passed" || patched.Status != "passed" || !baselineMarkerObserved || !patchedMarkerObserved {
		status = "failed"
		limitations = append(limitations, "Versioned reproduction proof requires both commands to pass and both invariant-specific markers to be observed in immutable worker output.")
	}
	evidence := []string{
		"invariant:" + invariant.InvariantRef,
		"worker_job:" + baselineJob.JobRef,
		"worker_job:" + patchedJob.JobRef,
		"verification:" + baseline.VerificationRef,
		"verification:" + patched.VerificationRef,
		"patch:" + strings.TrimSpace(patchRef),
	}
	payload := map[string]any{
		"invariant_ref":             invariant.InvariantRef,
		"patch_ref":                 strings.TrimSpace(patchRef),
		"baseline_job_ref":          baselineJob.JobRef,
		"patched_job_ref":           patchedJob.JobRef,
		"baseline_verification_ref": baseline.VerificationRef,
		"patched_verification_ref":  patched.VerificationRef,
		"baseline_marker_observed":  baselineMarkerObserved,
		"patched_marker_observed":   patchedMarkerObserved,
		"status":                    status,
	}
	runHash := hashJSON(payload)
	runRef := prefixedID("KRR1-", payload)
	proofRef := ""
	if status == "verified" {
		proofPayload := map[string]any{
			"invariant_ref": invariant.InvariantRef,
			"finding_ref":   invariant.FindingRef,
			"patch_ref":     strings.TrimSpace(patchRef),
			"before":        baseline.VerificationRef,
			"after":         patched.VerificationRef,
			"status":        "verified",
			"evidence":      evidence,
		}
		proofHash := hashJSON(proofPayload)
		proofRef = prefixedID("KPF1-", proofPayload)
		evidenceRaw, _ := json.Marshal(evidence)
		limitationsRaw, _ := json.Marshal(limitations)
		_, err = db.ExecContext(ctx, `INSERT INTO defense_proof_of_fix
			(proof_ref,program_id,network,finding_ref,patch_ref,before_verification_ref,after_verification_ref,status,evidence_refs,limitations,proof_hash,verdict_authority)
			VALUES($1,$2,$3,$4,$5,$6,$7,'verified',$8::jsonb,$9::jsonb,$10,false) ON CONFLICT(proof_ref) DO NOTHING`,
			proofRef, invariant.ProgramID, invariant.Network, invariant.FindingRef, strings.TrimSpace(patchRef),
			baseline.VerificationRef, patched.VerificationRef, string(evidenceRaw), string(limitationsRaw), proofHash)
		if err != nil {
			return ReproductionRun{}, err
		}
	}
	evidenceRaw, _ := json.Marshal(evidence)
	limitationsRaw, _ := json.Marshal(limitations)
	now := time.Now().UTC()
	_, err = db.ExecContext(ctx, `INSERT INTO defense_reproduction_runs
		(run_ref,invariant_ref,program_id,network,finding_ref,patch_ref,baseline_job_ref,patched_job_ref,baseline_verification_ref,patched_verification_ref,
		 baseline_marker_observed,patched_marker_observed,status,evidence_refs,limitations,run_hash,proof_ref,verdict_authority,created_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14::jsonb,$15::jsonb,$16,NULLIF($17,''),false,$18)
		ON CONFLICT(run_ref) DO NOTHING`, runRef, invariant.InvariantRef, invariant.ProgramID, invariant.Network, invariant.FindingRef,
		strings.TrimSpace(patchRef), baselineJob.JobRef, patchedJob.JobRef, baseline.VerificationRef, patched.VerificationRef,
		baselineMarkerObserved, patchedMarkerObserved, status, string(evidenceRaw), string(limitationsRaw), runHash, proofRef, now)
	if err != nil {
		return ReproductionRun{}, err
	}
	return ReproductionRun{RunRef: runRef, InvariantRef: invariant.InvariantRef, ProgramID: invariant.ProgramID, Network: invariant.Network,
		FindingRef: invariant.FindingRef, PatchRef: strings.TrimSpace(patchRef), BaselineJobRef: baselineJob.JobRef, PatchedJobRef: patchedJob.JobRef,
		BaselineVerificationRef: baseline.VerificationRef, PatchedVerificationRef: patched.VerificationRef,
		BaselineMarkerObserved: baselineMarkerObserved, PatchedMarkerObserved: patchedMarkerObserved, Status: status,
		EvidenceRefs: evidence, Limitations: limitations, RunHash: runHash, ProofRef: proofRef, VerdictAuthority: false, CreatedAt: now}, nil
}

func workerVerificationRef(job WorkerJob) (string, error) {
	verification, ok := job.Result["verification"].(map[string]any)
	if !ok {
		return "", errors.New("worker result contains no verification object")
	}
	ref, _ := verification["verification_ref"].(string)
	if strings.TrimSpace(ref) == "" {
		return "", errors.New("worker result contains no verification_ref")
	}
	return strings.TrimSpace(ref), nil
}

func loadStoredVerification(ctx context.Context, db *sql.DB, ref string) (storedVerification, error) {
	var item storedVerification
	var commandsRaw, resultsRaw []byte
	err := db.QueryRowContext(ctx, `SELECT verification_ref,program_id,network,COALESCE(finding_ref,''),source_artifact_ref,COALESCE(patch_ref,''),status,commands,command_results
		FROM defense_verification_runs WHERE verification_ref=$1`, strings.TrimSpace(ref)).Scan(&item.VerificationRef, &item.ProgramID, &item.Network,
		&item.FindingRef, &item.SourceArtifactRef, &item.PatchRef, &item.Status, &commandsRaw, &resultsRaw)
	if err != nil {
		return storedVerification{}, err
	}
	_ = json.Unmarshal(commandsRaw, &item.Commands)
	_ = json.Unmarshal(resultsRaw, &item.Results)
	return item, nil
}

func verificationBoundToInvariant(verification storedVerification, invariant ReproductionInvariant, patchRef string) bool {
	return verification.ProgramID == invariant.ProgramID && verification.Network == invariant.Network &&
		verification.FindingRef == invariant.FindingRef && verification.SourceArtifactRef == invariant.SourceArtifactRef &&
		verification.PatchRef == patchRef && len(verification.Commands) == 1 && verification.Commands[0] == invariant.Command
}

func verificationContainsMarker(verification storedVerification, marker string) bool {
	for _, result := range verification.Results {
		if result.Status == "passed" && strings.Contains(result.Output, marker) {
			return true
		}
	}
	return false
}

func ListReproductionRuns(ctx context.Context, db *sql.DB, findingRef string, limit int) ([]ReproductionRun, error) {
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx, `SELECT run_ref,invariant_ref,program_id,network,finding_ref,patch_ref,baseline_job_ref,patched_job_ref,
		baseline_verification_ref,patched_verification_ref,baseline_marker_observed,patched_marker_observed,status,evidence_refs,limitations,
		run_hash,COALESCE(proof_ref,''),verdict_authority,created_at FROM defense_reproduction_runs
		WHERE ($1='' OR finding_ref=$1) ORDER BY created_at DESC LIMIT $2`, strings.TrimSpace(findingRef), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []ReproductionRun{}
	for rows.Next() {
		var item ReproductionRun
		var evidenceRaw, limitationsRaw []byte
		if err := rows.Scan(&item.RunRef, &item.InvariantRef, &item.ProgramID, &item.Network, &item.FindingRef, &item.PatchRef,
			&item.BaselineJobRef, &item.PatchedJobRef, &item.BaselineVerificationRef, &item.PatchedVerificationRef,
			&item.BaselineMarkerObserved, &item.PatchedMarkerObserved, &item.Status, &evidenceRaw, &limitationsRaw,
			&item.RunHash, &item.ProofRef, &item.VerdictAuthority, &item.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evidenceRaw, &item.EvidenceRefs)
		_ = json.Unmarshal(limitationsRaw, &item.Limitations)
		out = append(out, item)
	}
	return out, rows.Err()
}

func ValidateReproductionMarkerOutput(output, marker string) error {
	if !reproductionMarkerPattern.MatchString(strings.TrimSpace(marker)) {
		return errors.New("invalid reproduction marker")
	}
	if !strings.Contains(output, marker) {
		return fmt.Errorf("required reproduction marker not observed: %s", marker)
	}
	return nil
}
