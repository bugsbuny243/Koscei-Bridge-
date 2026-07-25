package defense

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	WorkerActionVerifyBundle = "verify_bundle"
	defaultWorkerLease       = 10 * time.Minute
)

type WorkerJobRequest struct {
	Action             string            `json:"action"`
	SourceArtifactRef  string            `json:"source_artifact_ref,omitempty"`
	ProfileRef         string            `json:"profile_ref,omitempty"`
	MaterializationRef string            `json:"materialization_ref,omitempty"`
	FindingRef         string            `json:"finding_ref,omitempty"`
	PatchRef           string            `json:"patch_ref,omitempty"`
	Commands           []string          `json:"commands,omitempty"`
	Replacements       map[string]string `json:"replacements,omitempty"`
	MaxAttempts        int               `json:"max_attempts,omitempty"`
}

type WorkerJob struct {
	JobRef             string            `json:"job_ref"`
	Action             string            `json:"action"`
	ProgramID          string            `json:"program_id"`
	Network            string            `json:"network"`
	SourceArtifactRef  string            `json:"source_artifact_ref"`
	ProfileRef         string            `json:"profile_ref,omitempty"`
	MaterializationRef string            `json:"materialization_ref,omitempty"`
	FindingRef         string            `json:"finding_ref,omitempty"`
	PatchRef           string            `json:"patch_ref,omitempty"`
	Commands           []string          `json:"commands,omitempty"`
	Replacements       map[string]string `json:"replacements,omitempty"`
	RequestHash        string            `json:"request_hash"`
	Status             string            `json:"status"`
	Progress           int               `json:"progress"`
	Attempts           int               `json:"attempts"`
	MaxAttempts        int               `json:"max_attempts"`
	WorkerID           string            `json:"worker_id,omitempty"`
	LeaseExpiresAt     *time.Time         `json:"lease_expires_at,omitempty"`
	Result             map[string]any    `json:"result,omitempty"`
	ResultHash         string            `json:"result_hash,omitempty"`
	ErrorCode          string            `json:"error_code,omitempty"`
	ErrorMessage       string            `json:"error_message,omitempty"`
	QueuedAt           time.Time         `json:"queued_at"`
	StartedAt          *time.Time         `json:"started_at,omitempty"`
	CompletedAt        *time.Time         `json:"completed_at,omitempty"`
	FailedAt           *time.Time         `json:"failed_at,omitempty"`
	UpdatedAt          time.Time          `json:"updated_at"`
}

func EnqueueWorkerJob(ctx context.Context, db *sql.DB, request WorkerJobRequest) (WorkerJob, error) {
	if db == nil {
		return WorkerJob{}, errors.New("database unavailable")
	}
	request.Action = strings.ToLower(strings.TrimSpace(request.Action))
	request.SourceArtifactRef = strings.TrimSpace(request.SourceArtifactRef)
	request.ProfileRef = strings.TrimSpace(request.ProfileRef)
	request.MaterializationRef = strings.TrimSpace(request.MaterializationRef)
	request.FindingRef = strings.TrimSpace(request.FindingRef)
	request.PatchRef = strings.TrimSpace(request.PatchRef)

	var artifact Artifact
	var err error
	switch request.Action {
	case WorkerActionVerifyBundle:
		artifact, err = validateVerifyBundleWorkerRequest(ctx, db, &request)
	case WorkerActionRunLiteSVMHarness:
		artifact, err = validateLiteSVMWorkerRequest(ctx, db, &request)
	default:
		return WorkerJob{}, errors.New("unsupported defense worker action")
	}
	if err != nil {
		return WorkerJob{}, err
	}

	payload := map[string]any{
		"action": request.Action,
		"source_artifact_ref": artifact.ArtifactRef,
		"profile_ref": request.ProfileRef,
		"materialization_ref": request.MaterializationRef,
		"finding_ref": request.FindingRef,
		"patch_ref": request.PatchRef,
		"commands": request.Commands,
		"replacements": request.Replacements,
	}
	requestHash := hashJSON(payload)
	now := time.Now().UTC()
	identityPayload := map[string]any{"request_hash": requestHash, "queued_at": now.UnixNano()}
	if request.Action == WorkerActionVerifyBundle {
		payload["nonce"] = now.UnixNano()
		requestHash = hashJSON(payload)
		identityPayload = payload
	}
	jobRef := prefixedID("KDW1-", identityPayload)
	request.SourceArtifactRef = artifact.ArtifactRef
	requestRaw, _ := json.Marshal(request)

	_, err = db.ExecContext(ctx, `INSERT INTO defense_worker_jobs
		(job_ref,action,program_id,network,source_artifact_ref,finding_ref,patch_ref,request_payload,request_hash,status,progress,attempts,max_attempts,queued_at,updated_at,created_by)
		VALUES($1,$2,$3,$4,$5,NULLIF($6,''),NULLIF($7,''),$8::jsonb,$9,'queued',0,0,$10,$11,$11,'owner')
		ON CONFLICT DO NOTHING`,
		jobRef, request.Action, artifact.ProgramID, artifact.Network, artifact.ArtifactRef, request.FindingRef, request.PatchRef,
		string(requestRaw), requestHash, request.MaxAttempts, now)
	if err != nil {
		return WorkerJob{}, err
	}
	if request.Action == WorkerActionRunLiteSVMHarness {
		var activeRef string
		lookupErr := db.QueryRowContext(ctx, `SELECT job_ref FROM defense_worker_jobs
			WHERE action=$1 AND request_hash=$2 AND status IN ('queued','running')
			ORDER BY queued_at ASC LIMIT 1`, WorkerActionRunLiteSVMHarness, requestHash).Scan(&activeRef)
		if lookupErr != nil {
			return WorkerJob{}, lookupErr
		}
		if activeRef != jobRef {
			return GetWorkerJob(ctx, db, activeRef)
		}
	}
	job := WorkerJob{JobRef: jobRef, Action: request.Action, ProgramID: artifact.ProgramID, Network: artifact.Network,
		SourceArtifactRef: artifact.ArtifactRef, ProfileRef: request.ProfileRef, MaterializationRef: request.MaterializationRef,
		FindingRef: request.FindingRef, PatchRef: request.PatchRef, Commands: request.Commands, Replacements: request.Replacements,
		RequestHash: requestHash, Status: "queued", Progress: 0, Attempts: 0, MaxAttempts: request.MaxAttempts,
		QueuedAt: now, UpdatedAt: now}
	_ = appendWorkerEvent(ctx, db, jobRef, "queued", "", map[string]any{"request_hash": requestHash})
	return job, nil
}

func validateVerifyBundleWorkerRequest(ctx context.Context, db *sql.DB, request *WorkerJobRequest) (Artifact, error) {
	if request.SourceArtifactRef == "" {
		return Artifact{}, errors.New("source_artifact_ref is required")
	}
	if request.ProfileRef != "" || request.MaterializationRef != "" {
		return Artifact{}, errors.New("verification job cannot include harness execution references")
	}
	if request.MaxAttempts <= 0 || request.MaxAttempts > 5 {
		request.MaxAttempts = 2
	}
	if request.Replacements == nil {
		request.Replacements = map[string]string{}
	}
	for path, content := range request.Replacements {
		if _, err := safeRelativePath(path); err != nil {
			return Artifact{}, err
		}
		if len(content) > 300000 {
			return Artifact{}, errors.New("worker replacement file exceeds 300 KiB")
		}
	}
	if len(request.Replacements) > 20 {
		return Artifact{}, errors.New("too many worker replacement files")
	}
	if len(request.Commands) == 0 || len(request.Commands) > 5 {
		return Artifact{}, errors.New("one to five verification commands are required")
	}
	for _, command := range request.Commands {
		if _, ok := allowedCommand(command); !ok {
			return Artifact{}, fmt.Errorf("command is not allowlisted: %s", command)
		}
	}
	artifact, err := LoadArtifact(ctx, db, request.SourceArtifactRef)
	if err != nil {
		return Artifact{}, err
	}
	if artifact.ArtifactType != "source_bundle" && artifact.ArtifactType != "synthetic_source_bundle" {
		return Artifact{}, errors.New("defense worker requires a source bundle artifact")
	}
	return artifact, nil
}

func validateLiteSVMWorkerRequest(ctx context.Context, db *sql.DB, request *WorkerJobRequest) (Artifact, error) {
	if request.ProfileRef == "" || request.MaterializationRef == "" {
		return Artifact{}, errors.New("profile_ref and materialization_ref are required")
	}
	if request.SourceArtifactRef != "" || request.FindingRef != "" || request.PatchRef != "" || len(request.Commands) != 0 || len(request.Replacements) != 0 {
		return Artifact{}, errors.New("LiteSVM execution accepts only profile_ref and materialization_ref")
	}
	profile, err := LoadHarnessExecutionProfile(ctx, db, request.ProfileRef)
	if err != nil {
		return Artifact{}, errors.New("harness execution profile not found")
	}
	if profile.ReadinessStatus != "ready" || !profile.ExecutionAllowed || profile.Engine != HarnessEngineLiteSVM || !fixedLiteSVMProfileCommand(profile.CommandPolicy) {
		return Artifact{}, errors.New("harness execution profile is blocked or not a fixed LiteSVM profile")
	}
	materialization, err := LoadHarnessMaterialization(ctx, db, request.MaterializationRef)
	if err != nil {
		return Artifact{}, errors.New("harness materialization not found")
	}
	if materialization.ProfileRef != profile.ProfileRef || materialization.ProgramID != profile.ProgramID || materialization.Network != profile.Network ||
		materialization.Engine != HarnessEngineLiteSVM || materialization.Status != "ready" || materialization.NetworkAccess ||
		materialization.DependencyResolution || materialization.SourceExecuted || materialization.HarnessExecuted ||
		materialization.MainnetTransactionSent || materialization.VerdictAuthority {
		return Artifact{}, errors.New("harness materialization does not match the ready LiteSVM profile")
	}
	artifact, err := LoadArtifact(ctx, db, materialization.MaterializedArtifactRef)
	if err != nil {
		return Artifact{}, errors.New("materialized harness artifact not found")
	}
	if artifact.ArtifactType != "source_bundle" || artifact.ProgramID != profile.ProgramID || artifact.Network != profile.Network ||
		artifact.ContentHash != materialization.MaterializedBundleHash ||
		strings.ToLower(harnessArtifactMetadataString(artifact.Metadata, "artifact_role")) != "materialized_harness" ||
		harnessArtifactMetadataString(artifact.Metadata, "harness_profile_ref") != profile.ProfileRef {
		return Artifact{}, errors.New("materialized harness artifact does not match the execution evidence")
	}
	request.SourceArtifactRef = artifact.ArtifactRef
	request.Commands = []string{"cargo test --locked --offline"}
	request.Replacements = map[string]string{}
	if request.MaxAttempts <= 0 || request.MaxAttempts > 2 {
		request.MaxAttempts = 2
	}
	return artifact, nil
}

func ClaimWorkerJob(ctx context.Context, db *sql.DB, workerID string, lease time.Duration) (WorkerJob, bool, error) {
	if db == nil {
		return WorkerJob{}, false, errors.New("database unavailable")
	}
	workerID = strings.TrimSpace(workerID)
	if workerID == "" {
		return WorkerJob{}, false, errors.New("worker_id is required")
	}
	if lease <= 0 || lease > time.Hour {
		lease = defaultWorkerLease
	}
	var job WorkerJob
	var requestRaw []byte
	var leaseAt time.Time
	var recovered bool
	err := db.QueryRowContext(ctx, `WITH candidate AS (
		SELECT id,status FROM defense_worker_jobs
		WHERE attempts < max_attempts
		  AND (status='queued' OR (status='running' AND lease_expires_at < now()))
		ORDER BY CASE WHEN status='running' THEN 0 ELSE 1 END, queued_at ASC
		FOR UPDATE SKIP LOCKED
		LIMIT 1
	), claimed AS (
		UPDATE defense_worker_jobs j
		SET status='running',progress=10,attempts=j.attempts+1,worker_id=$1,
			lease_expires_at=now()+$2::interval,started_at=COALESCE(j.started_at,now()),updated_at=now(),
			error_code=NULL,error_message=NULL
		FROM candidate c WHERE j.id=c.id
		RETURNING j.job_ref,j.action,j.program_id,j.network,j.source_artifact_ref,COALESCE(j.finding_ref,''),COALESCE(j.patch_ref,''),
			j.request_payload,j.request_hash,j.status,j.progress,j.attempts,j.max_attempts,j.worker_id,j.lease_expires_at,j.queued_at,j.started_at,j.updated_at,
			(c.status='running') AS recovered
	)
	SELECT * FROM claimed`, workerID, fmt.Sprintf("%d seconds", int(lease.Seconds()))).Scan(
		&job.JobRef, &job.Action, &job.ProgramID, &job.Network, &job.SourceArtifactRef, &job.FindingRef, &job.PatchRef,
		&requestRaw, &job.RequestHash, &job.Status, &job.Progress, &job.Attempts, &job.MaxAttempts, &job.WorkerID,
		&leaseAt, &job.QueuedAt, &job.StartedAt, &job.UpdatedAt, &recovered)
	if errors.Is(err, sql.ErrNoRows) {
		return WorkerJob{}, false, nil
	}
	if err != nil {
		return WorkerJob{}, false, err
	}
	job.LeaseExpiresAt = &leaseAt
	var request WorkerJobRequest
	if err := json.Unmarshal(requestRaw, &request); err != nil {
		return WorkerJob{}, false, err
	}
	job.ProfileRef = request.ProfileRef
	job.MaterializationRef = request.MaterializationRef
	job.Commands = request.Commands
	job.Replacements = request.Replacements
	eventType := "claimed"
	if recovered {
		eventType = "lease_recovered"
	}
	_ = appendWorkerEvent(ctx, db, job.JobRef, eventType, workerID, map[string]any{"attempt": job.Attempts, "lease_expires_at": leaseAt})
	return job, true, nil
}

func CompleteWorkerJob(ctx context.Context, db *sql.DB, job WorkerJob, workerID string, result map[string]any) error {
	if db == nil {
		return errors.New("database unavailable")
	}
	resultRaw, _ := json.Marshal(result)
	resultHash := hashJSON(result)
	res, err := db.ExecContext(ctx, `UPDATE defense_worker_jobs SET status='completed',progress=100,result_payload=$3::jsonb,result_hash=$4,
		completed_at=now(),lease_expires_at=NULL,updated_at=now(),error_code=NULL,error_message=NULL
		WHERE job_ref=$1 AND status='running' AND worker_id=$2`, job.JobRef, workerID, string(resultRaw), resultHash)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected != 1 {
		return errors.New("worker job completion lease was lost")
	}
	return appendWorkerEvent(ctx, db, job.JobRef, "completed", workerID, map[string]any{"result_hash": resultHash})
}

func FailWorkerJob(ctx context.Context, db *sql.DB, job WorkerJob, workerID, code, message string) error {
	if db == nil {
		return errors.New("database unavailable")
	}
	code = strings.TrimSpace(code)
	message = strings.TrimSpace(message)
	if len(message) > 2000 {
		message = message[:2000]
	}
	res, err := db.ExecContext(ctx, `UPDATE defense_worker_jobs SET status='failed',progress=100,error_code=$3,error_message=$4,
		failed_at=now(),lease_expires_at=NULL,updated_at=now()
		WHERE job_ref=$1 AND status='running' AND worker_id=$2`, job.JobRef, workerID, code, message)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	if affected != 1 {
		return errors.New("worker job failure lease was lost")
	}
	return appendWorkerEvent(ctx, db, job.JobRef, "failed", workerID, map[string]any{"error_code": code, "error_message": message})
}

func ProcessWorkerJob(ctx context.Context, db *sql.DB, job WorkerJob, sandboxEnabled bool) (map[string]any, error) {
	switch job.Action {
	case WorkerActionVerifyBundle:
		artifact, err := LoadArtifact(ctx, db, job.SourceArtifactRef)
		if err != nil {
			return nil, err
		}
		report, err := VerifyBundle(ctx, artifact, job.FindingRef, job.PatchRef, job.Replacements, job.Commands, sandboxEnabled)
		if err != nil {
			return nil, err
		}
		if err := PersistVerification(ctx, db, report); err != nil {
			return nil, err
		}
		return map[string]any{
			"action": job.Action,
			"verification": report,
			"worker_execution": true,
			"mainnet_transaction_sent": false,
			"verdict_authority": false,
		}, nil
	case WorkerActionRunLiteSVMHarness:
		return nil, errors.New("Phase 12C LiteSVM execution runner is not enabled in this implementation slice")
	default:
		return nil, errors.New("unsupported worker action")
	}
}

func GetWorkerJob(ctx context.Context, db *sql.DB, jobRef string) (WorkerJob, error) {
	if db == nil {
		return WorkerJob{}, errors.New("database unavailable")
	}
	var job WorkerJob
	var requestRaw, resultRaw []byte
	var lease, started, completed, failed sql.NullTime
	err := db.QueryRowContext(ctx, `SELECT job_ref,action,program_id,network,source_artifact_ref,COALESCE(finding_ref,''),COALESCE(patch_ref,''),
		request_payload,request_hash,status,progress,attempts,max_attempts,COALESCE(worker_id,''),lease_expires_at,
		COALESCE(result_payload,'{}'::jsonb),COALESCE(result_hash,''),COALESCE(error_code,''),COALESCE(error_message,''),
		queued_at,started_at,completed_at,failed_at,updated_at FROM defense_worker_jobs WHERE job_ref=$1`, strings.TrimSpace(jobRef)).Scan(
		&job.JobRef, &job.Action, &job.ProgramID, &job.Network, &job.SourceArtifactRef, &job.FindingRef, &job.PatchRef,
		&requestRaw, &job.RequestHash, &job.Status, &job.Progress, &job.Attempts, &job.MaxAttempts, &job.WorkerID, &lease,
		&resultRaw, &job.ResultHash, &job.ErrorCode, &job.ErrorMessage, &job.QueuedAt, &started, &completed, &failed, &job.UpdatedAt)
	if err != nil {
		return WorkerJob{}, err
	}
	var request WorkerJobRequest
	_ = json.Unmarshal(requestRaw, &request)
	job.ProfileRef = request.ProfileRef
	job.MaterializationRef = request.MaterializationRef
	job.Commands = request.Commands
	job.Replacements = request.Replacements
	_ = json.Unmarshal(resultRaw, &job.Result)
	if lease.Valid {
		value := lease.Time
		job.LeaseExpiresAt = &value
	}
	if started.Valid {
		value := started.Time
		job.StartedAt = &value
	}
	if completed.Valid {
		value := completed.Time
		job.CompletedAt = &value
	}
	if failed.Valid {
		value := failed.Time
		job.FailedAt = &value
	}
	return job, nil
}

func ListWorkerJobs(ctx context.Context, db *sql.DB, status string, limit int) ([]WorkerJob, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	status = strings.ToLower(strings.TrimSpace(status))
	rows, err := db.QueryContext(ctx, `SELECT job_ref FROM defense_worker_jobs WHERE ($1='' OR status=$1) ORDER BY queued_at DESC LIMIT $2`, status, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	refs := []string{}
	for rows.Next() {
		var ref string
		if err := rows.Scan(&ref); err != nil {
			return nil, err
		}
		refs = append(refs, ref)
	}
	out := make([]WorkerJob, 0, len(refs))
	for _, ref := range refs {
		job, err := GetWorkerJob(ctx, db, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, job)
	}
	return out, rows.Err()
}

func appendWorkerEvent(ctx context.Context, db *sql.DB, jobRef, eventType, workerID string, payload map[string]any) error {
	if payload == nil {
		payload = map[string]any{}
	}
	eventPayload := map[string]any{"job_ref": jobRef, "event_type": eventType, "worker_id": workerID, "payload": payload, "at": time.Now().UTC().UnixNano()}
	eventHash := hashJSON(eventPayload)
	eventRef := prefixedID("KDWE1-", eventPayload)
	payloadRaw, _ := json.Marshal(payload)
	_, err := db.ExecContext(ctx, `INSERT INTO defense_worker_job_events(event_ref,job_ref,event_type,worker_id,payload,event_hash)
		VALUES($1,$2,$3,NULLIF($4,''),$5::jsonb,$6)`, eventRef, jobRef, eventType, workerID, string(payloadRaw), eventHash)
	return err
}
