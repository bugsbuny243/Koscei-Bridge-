package jobs

import (
	"context"
	"errors"
	"strings"
)

const (
	DefaultHistoryLimit = 100
	MaxHistoryLimit     = 200
)

// ListByUser returns durable jobs owned by one authenticated account. The
// optional jobType filter keeps customer history surfaces from mixing unrelated
// asynchronous workloads into a canonical investigation timeline.
func (s *Store) ListByUser(ctx context.Context, userID, jobType string, limit int) ([]Job, error) {
	if s == nil || s.DB == nil {
		return nil, errors.New("job store database unavailable")
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, errors.New("job history user id required")
	}
	jobType = strings.TrimSpace(jobType)
	if limit <= 0 {
		limit = DefaultHistoryLimit
	}
	if limit > MaxHistoryLimit {
		limit = MaxHistoryLimit
	}

	rows, err := s.DB.QueryContext(ctx, `
		SELECT id,user_id,email,job_type,status,network,target,request_payload,
		       COALESCE(result_payload,'null'::jsonb),COALESCE(error_code,''),COALESCE(error_message,''),
		       progress,attempts,queued_at,updated_at
		FROM web3_jobs
		WHERE user_id=$1 AND ($2='' OR job_type=$2)
		ORDER BY queued_at DESC,id DESC
		LIMIT $3`, userID, jobType, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []Job{}
	for rows.Next() {
		job, scanErr := scanJob(rows)
		if scanErr != nil {
			return nil, scanErr
		}
		out = append(out, job)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
