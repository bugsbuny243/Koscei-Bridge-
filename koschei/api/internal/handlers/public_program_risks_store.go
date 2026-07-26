package handlers

import (
	"context"
	"database/sql"
	"errors"
	"sort"
	"strings"
)

const publicProgramChangeSelect = `
	SELECT e.event_ref,e.program_id,e.network,e.change_types,e.severity,e.summary,e.created_at,
	       e.previous_snapshot_ref,e.current_snapshot_ref,
	       p.canonical_binary_hash,c.canonical_binary_hash,
	       COALESCE(p.upgrade_authority,''),COALESCE(c.upgrade_authority,''),
	       p.match_status,c.match_status,p.loader_kind,c.loader_kind,
	       COALESCE(p.programdata_address,''),COALESCE(c.programdata_address,''),
	       c.upgrade_authority_open,c.executable,e.evidence_refs,
	       pub.public_title,pub.public_summary
	FROM defense_program_change_events e
	JOIN defense_program_deployments p ON p.snapshot_ref=e.previous_snapshot_ref
	JOIN defense_program_deployments c ON c.snapshot_ref=e.current_snapshot_ref
	JOIN program_risk_publications pub ON pub.evidence_ref=e.event_ref AND pub.status='public'
	WHERE e.severity IN ('high','critical')
	  AND e.change_types ?| ARRAY['loader_changed','programdata_address_changed','bytecode_changed','upgrade_authority_opened','upgrade_authority_changed']`

const publicProgramSnapshotColumns = `
	d.snapshot_ref,d.program_id,d.network,d.loader_kind,COALESCE(d.programdata_address,''),
	COALESCE(d.upgrade_authority,''),d.upgrade_authority_open,d.executable,d.canonical_binary_hash,
	d.match_status,d.created_at,d.evidence_refs,pub.public_title,pub.public_summary`

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
			SELECT DISTINCT ON (program_id,network) *
			FROM defense_program_deployments
			ORDER BY program_id,network,created_at DESC,snapshot_ref DESC
		)
		SELECT `+publicProgramSnapshotColumns+`
		FROM latest d
		JOIN program_risk_publications pub ON pub.evidence_ref=d.snapshot_ref AND pub.status='public'
		WHERE d.upgrade_authority_open=true OR d.match_status='mismatched' OR d.executable=false
		ORDER BY d.created_at DESC LIMIT $1`, limit)
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
		FROM defense_program_deployments d
		JOIN program_risk_publications pub ON pub.evidence_ref=d.snapshot_ref AND pub.status='public'
		WHERE d.snapshot_ref=$1
		  AND (d.upgrade_authority_open=true OR d.match_status='mismatched' OR d.executable=false)
		  AND NOT EXISTS (
			SELECT 1 FROM defense_program_deployments newer
			WHERE newer.program_id=d.program_id AND newer.network=d.network
			  AND (newer.created_at>d.created_at OR (newer.created_at=d.created_at AND newer.snapshot_ref>d.snapshot_ref))
		  )`, ref))
}
