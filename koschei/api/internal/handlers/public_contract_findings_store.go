package handlers

import (
	"context"
	"database/sql"
	"errors"
	"strings"
)

const publicContractFindingSelect = `
	SELECT f.finding_ref,f.program_id,f.network,f.rule_id,
	       p.public_title,p.public_summary,f.severity,f.confidence,f.lifecycle_status,
	       f.details,a.content_hash,p.redaction_profile,p.published_at,f.created_at
	FROM defense_finding_publications p
	JOIN defense_program_findings f ON f.finding_ref=p.finding_ref
	JOIN defense_program_artifacts a ON a.artifact_ref=f.source_artifact_ref
	WHERE p.status='public'
	  AND f.severity IN ('high','critical')
	  AND f.confidence<>'unverified'
	  AND f.lifecycle_status<>'rejected'
	  AND a.trust_level IN ('observed','verified')`

type contractFindingEligibility struct {
	FindingRef    string
	RuleID        string
	FindingTitle  string
	Severity      string
	Confidence    string
	Lifecycle     string
	ArtifactTrust string
}

func (h *Handler) publicContractFindingDB() *sql.DB {
	if h == nil {
		return nil
	}
	if h.DBRead != nil {
		return h.DBRead
	}
	return h.DB
}

func (h *Handler) loadPublicContractFindings(ctx context.Context, limit int) ([]publicContractFinding, error) {
	db := h.publicContractFindingDB()
	if db == nil {
		return nil, errors.New("database unavailable")
	}
	if limit <= 0 || limit > 100 {
		limit = 24
	}
	rows, err := db.QueryContext(ctx, publicContractFindingSelect+` ORDER BY p.published_at DESC,f.finding_ref ASC LIMIT $1`, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]publicContractFinding, 0, limit)
	for rows.Next() {
		item, err := scanPublicContractFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func (h *Handler) loadPublicContractFindingByRef(ctx context.Context, ref string) (publicContractFinding, error) {
	ref = strings.TrimSpace(ref)
	if !publicContractFindingRefPattern.MatchString(ref) {
		return publicContractFinding{}, sql.ErrNoRows
	}
	db := h.publicContractFindingDB()
	if db == nil {
		return publicContractFinding{}, errors.New("database unavailable")
	}
	return scanPublicContractFinding(db.QueryRowContext(ctx, publicContractFindingSelect+` AND f.finding_ref=$1`, ref))
}

func loadContractFindingEligibility(ctx context.Context, db *sql.DB, ref string) (contractFindingEligibility, error) {
	var item contractFindingEligibility
	if db == nil {
		return item, errors.New("database unavailable")
	}
	err := db.QueryRowContext(ctx, `
		SELECT f.finding_ref,f.rule_id,f.title,f.severity,f.confidence,f.lifecycle_status,COALESCE(a.trust_level,'')
		FROM defense_program_findings f
		LEFT JOIN defense_program_artifacts a ON a.artifact_ref=f.source_artifact_ref
		WHERE f.finding_ref=$1`, strings.TrimSpace(ref)).Scan(
		&item.FindingRef, &item.RuleID, &item.FindingTitle, &item.Severity,
		&item.Confidence, &item.Lifecycle, &item.ArtifactTrust,
	)
	return item, err
}
