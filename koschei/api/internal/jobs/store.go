package jobs

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"koschei/api/internal/workerwake"
)

type Store struct{ DB *sql.DB }

type jobScanner interface {
	Scan(dest ...any) error
}

func NewStore(db *sql.DB) *Store { return &Store{DB: db} }

func (s *Store) Create(ctx context.Context, in CreateInput) (Job, error) {
	if s == nil || s.DB == nil {
		return Job{}, errors.New("job store database unavailable")
	}
	payload, err := json.Marshal(in.Request)
	if err != nil {
		return Job{}, err
	}
	job, err := scanJob(s.DB.QueryRowContext(ctx, `
		INSERT INTO web3_jobs (user_id,email,job_type,status,network,target,request_payload,progress)
		VALUES ($1,$2,$3,'queued',$4,$5,$6,0)
		RETURNING id,user_id,email,job_type,status,network,target,request_payload,
		          COALESCE(result_payload,'null'::jsonb),COALESCE(error_code,''),COALESCE(error_message,''),
		          progress,attempts,queued_at,updated_at`,
		in.UserID, in.Email, in.Type, in.Network, in.Target, payload,
	))
	if err == nil {
		signalCanonicalInvestigationJob(in.Type)
	}
	return job, err
}

// CreateUniqueActive serializes one logical investigation branch with a
// transaction-scoped advisory lock. The same root/depth/target branch is not
// duplicated while queued, running or already completed.
func (s *Store) CreateUniqueActive(ctx context.Context, in CreateInput, dedupeKey string) (Job, bool, error) {
	if s == nil || s.DB == nil {
		return Job{}, false, errors.New("job store database unavailable")
	}
	dedupeKey = strings.TrimSpace(dedupeKey)
	if dedupeKey == "" {
		job, err := s.Create(ctx, in)
		return job, true, err
	}
	payloadMap := map[string]any{}
	encoded, err := json.Marshal(in.Request)
	if err != nil {
		return Job{}, false, err
	}
	if len(encoded) > 0 && string(encoded) != "null" {
		_ = json.Unmarshal(encoded, &payloadMap)
	}
	payloadMap["dedupe_key"] = dedupeKey
	payload, err := json.Marshal(payloadMap)
	if err != nil {
		return Job{}, false, err
	}

	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return Job{}, false, err
	}
	defer tx.Rollback()
	lockKey := strings.Join([]string{in.Type, in.Network, in.Target, dedupeKey}, "|")
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock(hashtext($1))`, lockKey); err != nil {
		return Job{}, false, err
	}
	existing, err := scanJob(tx.QueryRowContext(ctx, `
		SELECT id,user_id,email,job_type,status,network,target,request_payload,
		       COALESCE(result_payload,'null'::jsonb),COALESCE(error_code,''),COALESCE(error_message,''),
		       progress,attempts,queued_at,updated_at
		FROM web3_jobs
		WHERE job_type=$1 AND COALESCE(network,'')=COALESCE($2,'') AND COALESCE(target,'')=COALESCE($3,'')
		  AND COALESCE(request_payload->>'dedupe_key','')=$4
		  AND status IN ('queued','running','completed')
		ORDER BY queued_at DESC
		LIMIT 1`, in.Type, in.Network, in.Target, dedupeKey))
	if err == nil {
		if commitErr := tx.Commit(); commitErr != nil {
			return Job{}, false, commitErr
		}
		if existing.Status == "queued" {
			signalCanonicalInvestigationJob(existing.Type)
		}
		return existing, false, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Job{}, false, err
	}
	created, err := scanJob(tx.QueryRowContext(ctx, `
		INSERT INTO web3_jobs (user_id,email,job_type,status,network,target,request_payload,progress)
		VALUES ($1,$2,$3,'queued',$4,$5,$6,0)
		RETURNING id,user_id,email,job_type,status,network,target,request_payload,
		          COALESCE(result_payload,'null'::jsonb),COALESCE(error_code,''),COALESCE(error_message,''),
		          progress,attempts,queued_at,updated_at`,
		in.UserID, in.Email, in.Type, in.Network, in.Target, payload,
	))
	if err != nil {
		return Job{}, false, err
	}
	if err := tx.Commit(); err != nil {
		return Job{}, false, err
	}
	// Signal only after commit (#697): a wake before the row is visible would be
	// coalesced away and the job would wait for the recovery ceiling.
	signalCanonicalInvestigationJob(created.Type)
	return created, true, nil
}

func (s *Store) Get(ctx context.Context, id, userID string) (Job, error) {
	if s == nil || s.DB == nil {
		return Job{}, errors.New("job store database unavailable")
	}
	q := `SELECT id,user_id,email,job_type,status,network,target,request_payload,
	             COALESCE(result_payload,'null'::jsonb),COALESCE(error_code,''),COALESCE(error_message,''),
	             progress,attempts,queued_at,updated_at FROM web3_jobs WHERE id=$1`
	args := []any{id}
	if userID != "" {
		q += ` AND user_id=$2`
		args = append(args, userID)
	}
	return scanJob(s.DB.QueryRowContext(ctx, q, args...))
}

// ClaimNext atomically leases one queued job. SKIP LOCKED permits multiple
// Railway instances without processing the same investigation twice.
func (s *Store) ClaimNext(ctx context.Context, jobTypes ...string) (Job, error) {
	if s == nil || s.DB == nil {
		return Job{}, errors.New("job store database unavailable")
	}
	clean := []string{}
	seen := map[string]bool{}
	for _, value := range jobTypes {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			clean = append(clean, value)
		}
	}
	if len(clean) == 0 {
		return Job{}, sql.ErrNoRows
	}
	placeholders := make([]string, len(clean))
	args := make([]any, len(clean))
	for index, value := range clean {
		placeholders[index] = fmt.Sprintf("$%d", index+1)
		args[index] = value
	}
	query := `
		WITH next_job AS (
			SELECT id
			FROM web3_jobs
			WHERE status='queued' AND attempts < max_attempts
			  AND job_type IN (` + strings.Join(placeholders, ",") + `)
			ORDER BY queued_at ASC,id ASC
			FOR UPDATE SKIP LOCKED
			LIMIT 1
		)
		UPDATE web3_jobs j
		SET status='running',progress=GREATEST(progress,5),attempts=attempts+1,
		    started_at=COALESCE(started_at,now()),updated_at=now(),error_code=NULL,error_message=NULL
		FROM next_job n
		WHERE j.id=n.id
		RETURNING j.id,j.user_id,j.email,j.job_type,j.status,j.network,j.target,j.request_payload,
		          COALESCE(j.result_payload,'null'::jsonb),COALESCE(j.error_code,''),COALESCE(j.error_message,''),
		          j.progress,j.attempts,j.queued_at,j.updated_at`
	return scanJob(s.DB.QueryRowContext(ctx, query, args...))
}

func (s *Store) RequeueStale(ctx context.Context, olderThan time.Duration) (int64, error) {
	if s == nil || s.DB == nil {
		return 0, errors.New("job store database unavailable")
	}
	if olderThan <= 0 {
		olderThan = 30 * time.Minute
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE web3_jobs
		SET status=CASE WHEN attempts < max_attempts THEN 'queued' ELSE 'failed' END,
		    progress=CASE WHEN attempts < max_attempts THEN LEAST(progress,10) ELSE progress END,
		    error_code=CASE WHEN attempts < max_attempts THEN NULL ELSE 'JOB_STALE_MAX_ATTEMPTS' END,
		    error_message=CASE WHEN attempts < max_attempts THEN NULL ELSE 'Investigation worker lease expired after maximum attempts.' END,
		    failed_at=CASE WHEN attempts < max_attempts THEN NULL ELSE now() END,
		    updated_at=now()
		WHERE status='running' AND updated_at < now() - ($1 * interval '1 second')`, int64(olderThan/time.Second))
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *Store) UpdateProgress(ctx context.Context, id string, progress int) error {
	if progress < 0 {
		progress = 0
	}
	if progress > 99 {
		progress = 99
	}
	_, err := s.DB.ExecContext(ctx, `UPDATE web3_jobs SET progress=$2,updated_at=now() WHERE id=$1 AND status='running'`, id, progress)
	return err
}

func (s *Store) MarkRunning(ctx context.Context, id string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE web3_jobs SET status='running',progress=10,attempts=attempts+1,started_at=COALESCE(started_at,now()),updated_at=now() WHERE id=$1`, id)
	return err
}

func (s *Store) Complete(ctx context.Context, id string, result any) error {
	b, err := json.Marshal(result)
	if err != nil {
		return err
	}
	_, err = s.DB.ExecContext(ctx, `UPDATE web3_jobs SET status='completed',progress=100,result_payload=$2,error_code=NULL,error_message=NULL,completed_at=now(),updated_at=now() WHERE id=$1`, id, b)
	return err
}

func (s *Store) Fail(ctx context.Context, id, code, message string) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE web3_jobs SET status='failed',error_code=$2,error_message=$3,failed_at=now(),updated_at=now() WHERE id=$1`, id, code, message)
	return err
}

func (s *Store) RetryOrFail(ctx context.Context, id, code, message string) (string, error) {
	var status string
	err := s.DB.QueryRowContext(ctx, `
		UPDATE web3_jobs
		SET status=CASE WHEN attempts < max_attempts THEN 'queued' ELSE 'failed' END,
		    progress=CASE WHEN attempts < max_attempts THEN 0 ELSE progress END,
		    error_code=$2,error_message=$3,
		    failed_at=CASE WHEN attempts < max_attempts THEN NULL ELSE now() END,
		    updated_at=now()
		WHERE id=$1
		RETURNING status`, id, code, message).Scan(&status)
	if err == nil && status == "queued" {
		workerwake.Signal(workerwake.CanonicalInvestigation)
	}
	return status, err
}

func signalCanonicalInvestigationJob(jobType string) {
	switch strings.TrimSpace(jobType) {
	case "canonical_investigation", "token_scan":
		workerwake.Signal(workerwake.CanonicalInvestigation)
	}
}

func scanJob(row jobScanner) (Job, error) {
	var job Job
	err := row.Scan(
		&job.ID, &job.UserID, &job.Email, &job.Type, &job.Status, &job.Network, &job.Target,
		&job.RequestPayload, &job.ResultPayload, &job.ErrorCode, &job.ErrorMessage,
		&job.Progress, &job.Attempts, &job.QueuedAt, &job.UpdatedAt,
	)
	return job, err
}
