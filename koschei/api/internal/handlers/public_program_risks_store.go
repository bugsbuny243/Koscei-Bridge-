package handlers

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
)

const publicProgramChangeSelect = `
	SELECT e.event_ref,e.program_id,e.network,e.change_types,e.severity,e.summary,e.event_hash,e.created_at,
	       e.previous_snapshot_ref,e.current_snapshot_ref,
	       p.canonical_binary_hash,c.canonical_binary_hash,
	       COALESCE(p.upgrade_authority,''),COALESCE(c.upgrade_authority,''),
	       p.match_status,c.match_status,p.loader_kind,c.loader_kind,
	       COALESCE(p.programdata_address,''),COALESCE(c.programdata_address,'')
	FROM defense_program_change_events e
	JOIN defense_program_deployments p ON p.snapshot_ref=e.previous_snapshot_ref
	JOIN defense_program_deployments c ON c.snapshot_ref=e.current_snapshot_ref
	WHERE e.severity IN ('high','critical')`

const publicProgramSnapshotColumns = `
	snapshot_ref,program_id,network,loader_kind,COALESCE(programdata_address,''),
	COALESCE(upgrade_authority,''),upgrade_authority_open,executable,canonical_binary_hash,
	match_status,snapshot_hash,created_at`

func (h *Handler) publicProgramRiskDB() *sql.DB {
	if h == nil {
		return nil
	}
	if h.DBRead != nil {
		return h.DBRead
	}
	return h.DB
}

func (h *Handler) loadPublicProgramRisks(ctx context.Context, limit int) ([]publicProgramRisk, error) {
	db := h.publicProgramRiskDB()
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	if limit <= 0 || limit > 100 {
		limit = 24
	}

	items := make([]publicProgramRisk, 0, limit*2)
	representedSnapshots := map[string]struct{}{}
	changeRows, err := db.QueryContext(ctx, publicProgramChangeSelect+` ORDER BY e.created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	for changeRows.Next() {
		item, scanErr := scanPublicProgramChange(changeRows)
		if scanErr != nil {
			changeRows.Close()
			return nil, scanErr
		}
		representedSnapshots[item.CurrentSnapshotRef] = struct{}{}
		items = append(items, item)
	}
	if err := changeRows.Err(); err != nil {
		changeRows.Close()
		return nil, err
	}
	changeRows.Close()

	snapshotRows, err := db.QueryContext(ctx, `
		WITH latest AS (
			SELECT DISTINCT ON (program_id,network) `+publicProgramSnapshotColumns+`
			FROM defense_program_deployments
			ORDER BY program_id,network,created_at DESC
		)
		SELECT `+publicProgramSnapshotColumns+`
		FROM latest
		WHERE upgrade_authority_open=true OR match_status='mismatched' OR executable=false
		ORDER BY created_at DESC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	for snapshotRows.Next() {
		item, scanErr := scanPublicProgramSnapshot(snapshotRows)
		if scanErr != nil {
			snapshotRows.Close()
			return nil, scanErr
		}
		if _, represented := representedSnapshots[item.CurrentSnapshotRef]; represented {
			continue
		}
		items = append(items, item)
	}
	if err := snapshotRows.Err(); err != nil {
		snapshotRows.Close()
		return nil, err
	}
	snapshotRows.Close()

	sort.SliceStable(items, func(i, j int) bool { return items[i].OccurredAt.After(items[j].OccurredAt) })
	if len(items) > limit {
		items = items[:limit]
	}
	return items, nil
}

func (h *Handler) loadPublicProgramRiskByRef(ctx context.Context, ref string) (publicProgramRisk, error) {
	ref = strings.TrimSpace(ref)
	if !publicProgramRiskRefPattern.MatchString(ref) {
		return publicProgramRisk{}, sql.ErrNoRows
	}
	db := h.publicProgramRiskDB()
	if db == nil {
		return publicProgramRisk{}, errors.New("database unavailable")
	}
	if strings.HasPrefix(ref, "KDCE1-") {
		return scanPublicProgramChange(db.QueryRowContext(ctx, publicProgramChangeSelect+` AND e.event_ref=$1`, ref))
	}
	return scanPublicProgramSnapshot(db.QueryRowContext(ctx, `
		SELECT `+publicProgramSnapshotColumns+`
		FROM defense_program_deployments
		WHERE snapshot_ref=$1
		  AND (upgrade_authority_open=true OR match_status='mismatched' OR executable=false)`, ref))
}
