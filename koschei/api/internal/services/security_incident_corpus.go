package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const SecurityIncidentCorpusSchemaVersion = "koschei-incident-corpus-v1"

type SecurityIncidentCorpusRecord struct {
	ID                 string         `json:"id,omitempty"`
	IncidentKey        string         `json:"incident_key"`
	SchemaVersion      string         `json:"schema_version"`
	Network            string         `json:"network"`
	Target             string         `json:"target"`
	ActorWallet        string         `json:"actor_wallet"`
	EventKind          string         `json:"event_kind"`
	SourceRuleID       string         `json:"source_rule_id"`
	EventSignature     string         `json:"event_signature"`
	EventSlot          int64          `json:"event_slot"`
	EventObservedAt    time.Time      `json:"event_observed_at"`
	VerdictID          string         `json:"verdict_id"`
	VerdictSignature   string         `json:"verdict_signature"`
	VerdictUpdatedAt   time.Time      `json:"verdict_updated_at"`
	VerdictRuleVersion string         `json:"verdict_rule_version"`
	Grade              string         `json:"grade"`
	RiskIndex          int            `json:"risk_index"`
	RiskLevel          string         `json:"risk_level"`
	Verdict            string         `json:"verdict"`
	Recommendation     string         `json:"recommendation"`
	Evidence           []string       `json:"evidence"`
	Signals            map[string]any `json:"signals"`
	VerdictSource      string         `json:"verdict_source"`
	RecordHash         string         `json:"record_hash"`
	SupersedesID       string         `json:"supersedes_incident_id,omitempty"`
	CreatedAt          time.Time      `json:"created_at,omitempty"`
}

type SecurityIncidentCorpusMaterialization struct {
	Network             string                         `json:"network"`
	Target              string                         `json:"target"`
	Status              string                         `json:"status"`
	Eligible            int                            `json:"eligible"`
	Inserted            int                            `json:"inserted"`
	AlreadyMaterialized int                            `json:"already_materialized"`
	Records             []SecurityIncidentCorpusRecord `json:"records"`
	Limitations         []string                       `json:"limitations"`
}

type SecurityIncidentCorpusView struct {
	Network                string                         `json:"network"`
	Target                 string                         `json:"target,omitempty"`
	ActorWallet            string                         `json:"actor_wallet,omitempty"`
	Available              bool                           `json:"available"`
	Complete               bool                           `json:"complete"`
	Status                 string                         `json:"status"`
	RecordCount            int                            `json:"record_count"`
	DistinctTargetCount    int                            `json:"distinct_target_count"`
	DistinctActorCount     int                            `json:"distinct_actor_count"`
	Records                []SecurityIncidentCorpusRecord `json:"records"`
	VerdictAuthority       bool                           `json:"verdict_authority"`
	RealWorldIdentityClaim bool                           `json:"real_world_identity_claim"`
	WrongdoingClaim        bool                           `json:"wrongdoing_claim"`
	Limitations            []string                       `json:"limitations"`
}

// Kept as the deterministic in-process representation used by unit tests and
// import tooling. Production materialization itself is owned by migration 096's
// PostgreSQL function so trigger-driven and explicit paths cannot diverge.
type securityIncidentCorpusCandidate struct {
	ActorWallet        string
	EventKind          string
	SourceRuleID       string
	EventSignature     string
	EventSlot          int64
	EventObservedAt    time.Time
	VerdictID          string
	VerdictSignature   string
	VerdictUpdatedAt   time.Time
	VerdictRuleVersion string
	Grade              string
	RiskIndex          int
	RiskLevel          string
	Verdict            string
	Recommendation     string
	EvidenceRaw        []byte
	SignalsRaw         []byte
	VerdictSource      string
}

// MaterializeVerifiedIncidentCorpus deliberately delegates to the same database
// function used by both source triggers. PostgreSQL is the single authority for
// corpus identity, version chaining and insertion. This avoids a second Go-side
// implementation drifting from trigger semantics.
func MaterializeVerifiedIncidentCorpus(ctx context.Context, db *sql.DB, network, target string) (SecurityIncidentCorpusMaterialization, error) {
	network = normalizeRadarNetwork(network)
	target = strings.TrimSpace(target)
	out := SecurityIncidentCorpusMaterialization{
		Network: network, Target: target, Status: "no_eligible_incidents",
		Records: []SecurityIncidentCorpusRecord{}, Limitations: []string{},
	}
	if db == nil {
		out.Status = "database_unavailable"
		out.Limitations = append(out.Limitations, "Incident corpus database is unavailable.")
		return out, nil
	}
	if target == "" {
		out.Status = "target_unavailable"
		out.Limitations = append(out.Limitations, "Incident corpus target is empty.")
		return out, nil
	}

	var inserted int
	if err := db.QueryRowContext(ctx, `SELECT public.materialize_security_incident_for_target($1,$2)`, network, target).Scan(&inserted); err != nil {
		if isSecurityRadarMissingRelation(err) || strings.Contains(strings.ToLower(err.Error()), "materialize_security_incident_for_target") {
			out.Status = "schema_unavailable"
			out.Limitations = append(out.Limitations, "Canonical incident corpus materializer is unavailable.")
			return out, nil
		}
		return out, err
	}

	view, err := LoadSecurityIncidentCorpus(ctx, db, network, target, "", 200)
	if err != nil {
		return out, err
	}
	out.Inserted = inserted
	out.Records = append(out.Records, view.Records...)
	out.Eligible = view.RecordCount
	if inserted > 0 {
		out.Status = "materialized"
	} else if view.RecordCount > 0 {
		out.Status = "already_materialized"
		out.AlreadyMaterialized = view.RecordCount
	}
	out.Limitations = append(out.Limitations,
		"Corpus eligibility proves a VERIFIED actor-linked on-chain event and a signed material token verdict coexisted; it does not prove the actor caused the verdict.",
		"Incident corpus records are append-only snapshots. Later verdict revisions create new corpus versions instead of rewriting earlier evidence.",
		"Database migration 096 is the canonical materialization and incident-key authority for both trigger and explicit paths.",
	)
	return out, nil
}

func LoadSecurityIncidentCorpus(ctx context.Context, db *sql.DB, network, target, actorWallet string, limit int) (SecurityIncidentCorpusView, error) {
	network = normalizeRadarNetwork(network)
	target = strings.TrimSpace(target)
	actorWallet = strings.TrimSpace(actorWallet)
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	out := SecurityIncidentCorpusView{
		Network: network, Target: target, ActorWallet: actorWallet, Complete: true, Status: "no_incidents",
		Records: []SecurityIncidentCorpusRecord{}, VerdictAuthority: false, RealWorldIdentityClaim: false,
		WrongdoingClaim: false, Limitations: []string{},
	}
	if db == nil {
		out.Status = "database_unavailable"
		out.Complete = false
		out.Limitations = append(out.Limitations, "Incident corpus database is unavailable.")
		return out, nil
	}

	args := []any{network}
	where := []string{"network=$1"}
	if target != "" {
		args = append(args, target)
		// Solana public keys are base58 identifiers and case-sensitive.
		where = append(where, fmt.Sprintf("target=$%d", len(args)))
	}
	if actorWallet != "" {
		args = append(args, actorWallet)
		where = append(where, fmt.Sprintf("actor_wallet=$%d", len(args)))
	}
	args = append(args, limit)
	query := `
		SELECT id::text,incident_key,schema_version,network,target,actor_wallet,event_kind,source_rule_id,
		       event_signature,event_slot,event_observed_at,verdict_id::text,verdict_signature,verdict_updated_at,
		       verdict_rule_version,grade,risk_index,risk_level,verdict,recommendation,evidence,signals,
		       verdict_source,record_hash,COALESCE(supersedes_incident_id::text,''),created_at
		FROM security_incident_corpus
		WHERE ` + strings.Join(where, " AND ") + `
		ORDER BY created_at DESC,id DESC
		LIMIT $` + fmt.Sprintf("%d", len(args))
	rows, err := db.QueryContext(ctx, query, args...)
	if err != nil {
		if isSecurityRadarMissingRelation(err) {
			out.Status = "schema_unavailable"
			out.Complete = false
			return out, nil
		}
		return out, err
	}
	defer rows.Close()

	targets, actors := map[string]bool{}, map[string]bool{}
	for rows.Next() {
		var item SecurityIncidentCorpusRecord
		var evidenceRaw, signalsRaw []byte
		if err := rows.Scan(
			&item.ID, &item.IncidentKey, &item.SchemaVersion, &item.Network, &item.Target, &item.ActorWallet,
			&item.EventKind, &item.SourceRuleID, &item.EventSignature, &item.EventSlot, &item.EventObservedAt,
			&item.VerdictID, &item.VerdictSignature, &item.VerdictUpdatedAt, &item.VerdictRuleVersion,
			&item.Grade, &item.RiskIndex, &item.RiskLevel, &item.Verdict, &item.Recommendation,
			&evidenceRaw, &signalsRaw, &item.VerdictSource, &item.RecordHash, &item.SupersedesID, &item.CreatedAt,
		); err != nil {
			return out, err
		}
		_ = json.Unmarshal(evidenceRaw, &item.Evidence)
		_ = json.Unmarshal(signalsRaw, &item.Signals)
		if item.Evidence == nil {
			item.Evidence = []string{}
		}
		if item.Signals == nil {
			item.Signals = map[string]any{}
		}
		out.Records = append(out.Records, item)
		targets[item.Target], actors[item.ActorWallet] = true, true
	}
	if err := rows.Err(); err != nil {
		return out, err
	}
	out.RecordCount = len(out.Records)
	out.DistinctTargetCount, out.DistinctActorCount = len(targets), len(actors)
	out.Available = out.RecordCount > 0
	if out.Available {
		out.Status = "verified_incidents_observed"
	}
	out.Limitations = append(out.Limitations,
		"Corpus rows are immutable evidence snapshots and have no verdict authority by themselves.",
		"Actor wallet means an exact on-chain address involved in the verified source event; it is not a real-world identity claim.",
		"Solana target and actor identifiers are matched exactly; no case folding is applied.",
	)
	return out, nil
}

func securityIncidentCorpusRecordFromCandidate(network, target string, candidate securityIncidentCorpusCandidate) (SecurityIncidentCorpusRecord, error) {
	record := SecurityIncidentCorpusRecord{
		SchemaVersion: SecurityIncidentCorpusSchemaVersion,
		Network:       normalizeRadarNetwork(network), Target: strings.TrimSpace(target),
		ActorWallet: strings.TrimSpace(candidate.ActorWallet), EventKind: strings.TrimSpace(candidate.EventKind),
		SourceRuleID: strings.TrimSpace(candidate.SourceRuleID), EventSignature: strings.TrimSpace(candidate.EventSignature),
		EventSlot: candidate.EventSlot, EventObservedAt: candidate.EventObservedAt.UTC(),
		VerdictID: strings.TrimSpace(candidate.VerdictID), VerdictSignature: strings.TrimSpace(candidate.VerdictSignature),
		VerdictUpdatedAt: candidate.VerdictUpdatedAt.UTC(), VerdictRuleVersion: strings.TrimSpace(candidate.VerdictRuleVersion),
		Grade: strings.TrimSpace(candidate.Grade), RiskIndex: candidate.RiskIndex,
		RiskLevel: securityIncidentMaterialRiskLevel(candidate.RiskLevel, candidate.RiskIndex),
		Verdict:   strings.TrimSpace(candidate.Verdict), Recommendation: strings.TrimSpace(candidate.Recommendation),
		Evidence: []string{}, Signals: map[string]any{}, VerdictSource: strings.TrimSpace(candidate.VerdictSource),
	}
	if record.ActorWallet == "" || record.Target == "" || record.EventKind == "" || record.SourceRuleID == "" || record.EventSignature == "" || record.EventSlot <= 0 || record.VerdictID == "" || record.VerdictSignature == "" || record.VerdictRuleVersion == "" {
		return SecurityIncidentCorpusRecord{}, fmt.Errorf("incident corpus candidate has incomplete evidence references")
	}
	if !record.EventObservedAt.IsZero() && record.EventObservedAt.After(time.Now().UTC().Add(5*time.Minute)) {
		return SecurityIncidentCorpusRecord{}, fmt.Errorf("incident corpus event timestamp is in the future")
	}
	_ = json.Unmarshal(candidate.EvidenceRaw, &record.Evidence)
	_ = json.Unmarshal(candidate.SignalsRaw, &record.Signals)
	if record.Evidence == nil {
		record.Evidence = []string{}
	}
	if record.Signals == nil {
		record.Signals = map[string]any{}
	}
	record.IncidentKey = securityIncidentCorpusIncidentKey(record)
	record.RecordHash = securityIncidentCorpusRecordHash(record)
	return record, nil
}

// This helper mirrors migration 096 exactly for offline/import validation. The
// canonical timestamp component is epoch microseconds, not a formatted time.
func securityIncidentCorpusIncidentKey(record SecurityIncidentCorpusRecord) string {
	canonical := strings.Join([]string{
		record.SchemaVersion, record.Network, record.Target, record.ActorWallet, record.EventKind,
		record.SourceRuleID, record.EventSignature, fmt.Sprintf("%d", record.EventSlot),
		record.VerdictID, record.VerdictSignature, fmt.Sprintf("%d", record.VerdictUpdatedAt.UTC().UnixMicro()),
	}, "\x1f")
	digest := sha256.Sum256([]byte(canonical))
	return "KIC1-" + hex.EncodeToString(digest[:])
}

func securityIncidentCorpusRecordHash(record SecurityIncidentCorpusRecord) string {
	canonical := struct {
		SchemaVersion      string         `json:"schema_version"`
		Network            string         `json:"network"`
		Target             string         `json:"target"`
		ActorWallet        string         `json:"actor_wallet"`
		EventKind          string         `json:"event_kind"`
		SourceRuleID       string         `json:"source_rule_id"`
		EventSignature     string         `json:"event_signature"`
		EventSlot          int64          `json:"event_slot"`
		EventObservedAt    string         `json:"event_observed_at"`
		VerdictID          string         `json:"verdict_id"`
		VerdictSignature   string         `json:"verdict_signature"`
		VerdictUpdatedAt   string         `json:"verdict_updated_at"`
		VerdictRuleVersion string         `json:"verdict_rule_version"`
		Grade              string         `json:"grade"`
		RiskIndex          int            `json:"risk_index"`
		RiskLevel          string         `json:"risk_level"`
		Verdict            string         `json:"verdict"`
		Recommendation     string         `json:"recommendation"`
		Evidence           []string       `json:"evidence"`
		Signals            map[string]any `json:"signals"`
		VerdictSource      string         `json:"verdict_source"`
	}{
		record.SchemaVersion, record.Network, record.Target, record.ActorWallet, record.EventKind,
		record.SourceRuleID, record.EventSignature, record.EventSlot, record.EventObservedAt.UTC().Format(time.RFC3339Nano),
		record.VerdictID, record.VerdictSignature, record.VerdictUpdatedAt.UTC().Format(time.RFC3339Nano),
		record.VerdictRuleVersion, record.Grade, record.RiskIndex, record.RiskLevel, record.Verdict,
		record.Recommendation, append([]string{}, record.Evidence...), nonNilMap(record.Signals), record.VerdictSource,
	}
	payload, _ := json.Marshal(canonical)
	digest := sha256.Sum256(payload)
	return "sha256:" + hex.EncodeToString(digest[:])
}

func securityIncidentMaterialRiskLevel(level string, index int) string {
	switch strings.ToLower(strings.TrimSpace(level)) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	}
	if index >= 80 {
		return "critical"
	}
	return "high"
}
