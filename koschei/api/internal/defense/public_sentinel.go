package defense

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

// SubscribeProgramMonitor creates or reuses one global on-chain monitor and
// records an authenticated user/API subscription. A shared program monitor is
// never reassigned to a later subscriber.
func SubscribeProgramMonitor(ctx context.Context, db *sql.DB, input ProgramMonitorInput, subject string) (ProgramMonitor, error) {
	if db == nil {
		return ProgramMonitor{}, errors.New("database unavailable")
	}
	subject = strings.TrimSpace(subject)
	input.ProgramID = strings.TrimSpace(input.ProgramID)
	input.Network = normalizedNetwork(input.Network)
	input.ManifestArtifactRef = strings.TrimSpace(input.ManifestArtifactRef)
	if subject == "" || input.ProgramID == "" {
		return ProgramMonitor{}, errors.New("subject and program_id are required")
	}
	if input.IntervalSeconds == 0 {
		input.IntervalSeconds = 900
	}
	if input.IntervalSeconds < 60 || input.IntervalSeconds > 86400 {
		return ProgramMonitor{}, errors.New("interval_seconds must be between 60 and 86400")
	}
	if input.ManifestArtifactRef != "" {
		artifact, err := LoadArtifact(ctx, db, input.ManifestArtifactRef)
		if err != nil {
			return ProgramMonitor{}, errors.New("manifest artifact not found")
		}
		if artifact.ProgramID != input.ProgramID || normalizedNetwork(artifact.Network) != input.Network ||
			(artifact.ArtifactType != "source_manifest" && artifact.ArtifactType != "sbpf_manifest") {
			return ProgramMonitor{}, errors.New("manifest artifact does not match the monitored program")
		}
		if subject != "owner" {
			var subscribed bool
			if err := db.QueryRowContext(ctx, `SELECT EXISTS(
				SELECT 1 FROM defense_artifact_subscriptions WHERE artifact_ref=$1 AND auth_subject=$2)`, input.ManifestArtifactRef, subject).Scan(&subscribed); err != nil {
				return ProgramMonitor{}, err
			}
			if !subscribed {
				return ProgramMonitor{}, errors.New("manifest artifact belongs to another principal")
			}
		}
	}

	identity := map[string]any{"program_id": input.ProgramID, "network": input.Network}
	monitorRef := prefixedID("KDM1-", identity)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ProgramMonitor{}, err
	}
	defer tx.Rollback()

	var existingManifest sql.NullString
	err = tx.QueryRowContext(ctx, `SELECT manifest_artifact_ref FROM defense_program_monitors
		WHERE program_id=$1 AND network=$2 FOR UPDATE`, input.ProgramID, input.Network).Scan(&existingManifest)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return ProgramMonitor{}, err
	}
	if err == nil && input.ManifestArtifactRef != "" && existingManifest.Valid && strings.TrimSpace(existingManifest.String) != "" && existingManifest.String != input.ManifestArtifactRef {
		return ProgramMonitor{}, errors.New("shared monitor already uses a different manifest")
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO defense_program_monitors
		(monitor_ref,program_id,network,manifest_artifact_ref,active,interval_seconds,next_check_at,last_status,created_by)
		VALUES($1,$2,$3,NULLIF($4,''),true,$5,now(),'pending',$6)
		ON CONFLICT(program_id,network) DO UPDATE SET
			manifest_artifact_ref=COALESCE(defense_program_monitors.manifest_artifact_ref,EXCLUDED.manifest_artifact_ref),
			active=true,
			next_check_at=LEAST(defense_program_monitors.next_check_at,now()),
			last_status=CASE WHEN defense_program_monitors.last_status='disabled' THEN 'pending' ELSE defense_program_monitors.last_status END,
			last_error=NULL,
			updated_at=now()`, monitorRef, input.ProgramID, input.Network, input.ManifestArtifactRef, input.IntervalSeconds, subject)
	if err != nil {
		return ProgramMonitor{}, err
	}
	if _, err := tx.ExecContext(ctx, `INSERT INTO defense_program_monitor_subscriptions
		(monitor_ref,auth_subject,active,created_at,updated_at)
		VALUES($1,$2,true,now(),now())
		ON CONFLICT(monitor_ref,auth_subject) DO UPDATE SET active=true,updated_at=now()`, monitorRef, subject); err != nil {
		return ProgramMonitor{}, err
	}
	if err := tx.Commit(); err != nil {
		return ProgramMonitor{}, err
	}
	return GetProgramMonitor(ctx, db, monitorRef)
}

func ListSubscribedProgramMonitors(ctx context.Context, db *sql.DB, subject string, activeOnly bool, limit int) ([]ProgramMonitor, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	subject = strings.TrimSpace(subject)
	if subject == "" {
		return nil, errors.New("subject is required")
	}
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	rows, err := db.QueryContext(ctx, `SELECT m.monitor_ref
		FROM defense_program_monitor_subscriptions s
		JOIN defense_program_monitors m ON m.monitor_ref=s.monitor_ref
		WHERE s.auth_subject=$1 AND s.active=true AND (NOT $2 OR m.active=true)
		ORDER BY m.updated_at DESC LIMIT $3`, subject, activeOnly, limit)
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
	out := make([]ProgramMonitor, 0, len(refs))
	for _, ref := range refs {
		item, err := GetProgramMonitor(ctx, db, ref)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func GetSubscribedProgramMonitor(ctx context.Context, db *sql.DB, monitorRef, subject string) (ProgramMonitor, error) {
	monitorRef = strings.TrimSpace(monitorRef)
	subject = strings.TrimSpace(subject)
	var exists bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM defense_program_monitor_subscriptions
		WHERE monitor_ref=$1 AND auth_subject=$2 AND active=true)`, monitorRef, subject).Scan(&exists)
	if err != nil {
		return ProgramMonitor{}, err
	}
	if !exists {
		return ProgramMonitor{}, sql.ErrNoRows
	}
	return GetProgramMonitor(ctx, db, monitorRef)
}

func UnsubscribeProgramMonitor(ctx context.Context, db *sql.DB, monitorRef, subject string) (ProgramMonitor, error) {
	if db == nil {
		return ProgramMonitor{}, errors.New("database unavailable")
	}
	monitorRef = strings.TrimSpace(monitorRef)
	subject = strings.TrimSpace(subject)
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return ProgramMonitor{}, err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE defense_program_monitor_subscriptions
		SET active=false,updated_at=now() WHERE monitor_ref=$1 AND auth_subject=$2 AND active=true`, monitorRef, subject)
	if err != nil {
		return ProgramMonitor{}, err
	}
	affected, _ := res.RowsAffected()
	if affected != 1 {
		return ProgramMonitor{}, sql.ErrNoRows
	}
	_, err = tx.ExecContext(ctx, `UPDATE defense_program_monitors m SET active=false,last_status='disabled',updated_at=now()
		WHERE m.monitor_ref=$1 AND m.created_by<>'owner'
		  AND NOT EXISTS(SELECT 1 FROM defense_program_monitor_subscriptions s WHERE s.monitor_ref=m.monitor_ref AND s.active=true)`, monitorRef)
	if err != nil {
		return ProgramMonitor{}, err
	}
	if err := tx.Commit(); err != nil {
		return ProgramMonitor{}, err
	}
	return GetProgramMonitor(ctx, db, monitorRef)
}
