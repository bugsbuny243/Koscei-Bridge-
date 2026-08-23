package handlers

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sort"
	"strings"
)

const maxTransactionGuardDeploymentSnapshotLookup = 64

type transactionGuardDeploymentSnapshot struct {
	SnapshotRef          string
	ProgramID            string
	Network              string
	LoaderID             string
	LoaderKind           string
	ProgramDataAddress   string
	AccountSlot          uint64
	DeploymentSlot       uint64
	UpgradeAuthority     string
	UpgradeAuthorityOpen bool
	Executable           bool
	CanonicalBinaryHash  string
	SourceCommit         string
	MatchStatus          string
	MatchEvidenceStatus  string
	SnapshotHash         string
	VerdictAuthority     bool
}

// latestTransactionGuardDeploymentSnapshots is a read-only compatibility
// lookup for Transaction Guard. It intentionally owns no Defense OS behavior:
// no RPC, source import, compilation, artifact mutation or execution occurs.
func latestTransactionGuardDeploymentSnapshots(ctx context.Context, db *sql.DB, network string, programIDs []string) (map[string]transactionGuardDeploymentSnapshot, error) {
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	ids, err := normalizeTransactionGuardDeploymentLookup(programIDs)
	if err != nil {
		return nil, err
	}
	out := make(map[string]transactionGuardDeploymentSnapshot, len(ids))
	if len(ids) == 0 {
		return out, nil
	}

	network = normalizeTransactionGuardDeploymentNetwork(network)
	args := make([]any, 0, len(ids)+1)
	args = append(args, network)
	placeholders := make([]string, 0, len(ids))
	for index, programID := range ids {
		placeholders = append(placeholders, fmt.Sprintf("$%d", index+2))
		args = append(args, programID)
	}
	query := `SELECT DISTINCT ON (program_id)
		program_id,snapshot_ref,network,loader_id,loader_kind,COALESCE(programdata_address,''),account_slot,
		COALESCE(deployment_slot,0),COALESCE(upgrade_authority,''),upgrade_authority_open,executable,canonical_binary_hash,
		COALESCE(source_commit,''),match_status,match_evidence_status,snapshot_hash,verdict_authority
		FROM defense_program_deployments
		WHERE network=$1 AND program_id IN (` + strings.Join(placeholders, ",") + `)
		ORDER BY program_id,created_at DESC,snapshot_ref DESC`
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var item transactionGuardDeploymentSnapshot
		if err := rows.Scan(
			&item.ProgramID, &item.SnapshotRef, &item.Network, &item.LoaderID, &item.LoaderKind, &item.ProgramDataAddress,
			&item.AccountSlot, &item.DeploymentSlot, &item.UpgradeAuthority, &item.UpgradeAuthorityOpen, &item.Executable,
			&item.CanonicalBinaryHash, &item.SourceCommit, &item.MatchStatus, &item.MatchEvidenceStatus, &item.SnapshotHash,
			&item.VerdictAuthority,
		); err != nil {
			return nil, err
		}
		item.ProgramID = strings.TrimSpace(item.ProgramID)
		if item.ProgramID == "" || normalizeTransactionGuardDeploymentNetwork(item.Network) != network {
			return nil, errors.New("deployment snapshot identity mismatch")
		}
		out[item.ProgramID] = item
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func normalizeTransactionGuardDeploymentLookup(programIDs []string) ([]string, error) {
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
	if len(ids) > maxTransactionGuardDeploymentSnapshotLookup {
		return nil, fmt.Errorf("program deployment lookup exceeds limit %d", maxTransactionGuardDeploymentSnapshotLookup)
	}
	sort.Strings(ids)
	return ids, nil
}

func normalizeTransactionGuardDeploymentNetwork(network string) string {
	network = strings.TrimSpace(network)
	if network == "" {
		return "solana-mainnet"
	}
	return network
}
