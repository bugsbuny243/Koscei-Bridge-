package defense

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const maxProgramDeploymentSnapshotLookup = 64

// LatestDeploymentSnapshots returns at most one immutable Defense OS deployment
// snapshot for each requested program. It is read-only and never triggers RPC,
// source import, compilation or program execution.
func LatestDeploymentSnapshots(ctx context.Context, db *sql.DB, network string, programIDs []string) (map[string]DeploymentSnapshot, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	ids, err := normalizeDeploymentSnapshotLookup(programIDs)
	if err != nil {
		return nil, err
	}
	out := make(map[string]DeploymentSnapshot, len(ids))
	if len(ids) == 0 {
		return out, nil
	}

	args := make([]any, 0, len(ids)+1)
	args = append(args, normalizedNetwork(network))
	placeholders := make([]string, 0, len(ids))
	for index, programID := range ids {
		placeholders = append(placeholders, fmt.Sprintf("$%d", index+2))
		args = append(args, programID)
	}
	query := `SELECT DISTINCT ON (program_id) program_id,snapshot_ref
		FROM defense_program_deployments
		WHERE network=$1 AND program_id IN (` + strings.Join(placeholders, ",") + `)
		ORDER BY program_id,created_at DESC,snapshot_ref DESC`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	refs := make(map[string]string, len(ids))
	for rows.Next() {
		var programID, snapshotRef string
		if err := rows.Scan(&programID, &snapshotRef); err != nil {
			return nil, err
		}
		programID = strings.TrimSpace(programID)
		snapshotRef = strings.TrimSpace(snapshotRef)
		if programID != "" && snapshotRef != "" {
			refs[programID] = snapshotRef
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}

	for _, programID := range ids {
		ref := refs[programID]
		if ref == "" {
			continue
		}
		snapshot, err := loadDeploymentSnapshot(ctx, db, ref)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(snapshot.ProgramID) != programID || normalizedNetwork(snapshot.Network) != normalizedNetwork(network) {
			return nil, errors.New("deployment snapshot identity mismatch")
		}
		out[programID] = snapshot
	}
	return out, nil
}

func normalizeDeploymentSnapshotLookup(programIDs []string) ([]string, error) {
	seen := map[string]struct{}{}
	ids := make([]string, 0, len(programIDs))
	for _, raw := range programIDs {
		programID := strings.TrimSpace(raw)
		if programID == "" {
			continue
		}
		if _, exists := seen[programID]; exists {
			continue
		}
		seen[programID] = struct{}{}
		ids = append(ids, programID)
	}
	if len(ids) > maxProgramDeploymentSnapshotLookup {
		return nil, fmt.Errorf("program deployment lookup exceeds limit %d", maxProgramDeploymentSnapshotLookup)
	}
	sort.Strings(ids)
	return ids, nil
}
