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

const (
	SecurityIncidentCorpusSchemaVersion = "koschei-incident-corpus-v1"
	securityIncidentCorpusQueryLimit    = 128
)

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
	Network           string                         `json:"network"`
	Target            string                         `json:"target"`
	Status            string                         `json:"status"`
	Eligible          int                            `json:"eligible"`
	Inserted          int                            `json:"inserted"`
	AlreadyMaterialized int                          `json:"already_materialized"`
	Records           []SecurityIncidentCorpusRecord `json:"records"`
	Limitations       []string                       `json:"limitations"`
}

type SecurityIncidentCorpusView struct {
	Network                string                         `json:"network"`
	Target                 string                         `json:"target,omitempty"`
	ActorWallet            string                         `json:"actor_wallet,omitempty"`
	Available              bool                           `json:"available"`
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

// MaterializeVerifiedIncidentCorpus persists only a strict conjunction of
// transaction-referenced VERIFIED actor events and Koschei-signed material final
// verdicts for the same target. The row is historical evidence context; it does
// not assert actor causation, common real-world identity, intent or wrongdoing.
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

	candidates, err := loadSecurityIncidentCorpusCandidates(ctx, db, network, target)
	if err != nil {
		if isSecurityRadarMissingRelation(err) {
			out.Status = "schema_unavailable"
			out.Limitations = append(out.Limitations, "Incident corpus or source evidence schema is unavailable.")
			return out, nil
		}
		return out, err
	}
	out.Eligible = len(candidates)
	for _, candidate := range candidates {
		record, err := securityIncidentCorpusRecordFromCandidate(network, target, candidate)
		if err != nil {
			return out, err
		}
		inserted, persisted, err := insertSecurityIncidentCorpusRecord(ctx, db, record)
		if err != nil {
			return out, err
		}
		if inserted {
			out.Inserted++
		} else {
			out.AlreadyMaterialized++
		}
		out.Records = append(out.Records, persisted)
	}
	if out.Eligible > 0 {
		out.Status = "materialized"
		if out.Inserted == 0 {
			out.Status = "already_materialized"
		}
	}
	out.Limitations = append(out.Limitations,
		"Corpus eligibility proves a VERIFIED actor-linked on-chain event and a signed material token verdict coexisted; it does not prove the actor caused the verdict.",
		"Incident corpus records are append-only snapshots. Later verdict revisions create new corpus versions instead of rewriting earlier evidence.",
	)
	return out, nil
}

func loadSecurityIncidentCorpusCandidates(ctx context.Context, db *sql.DB, network, target string) ([]securityIncidentCorpusCandidate, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT
			e.actor_wallet,e.event_kind,e.source_rule_id,e.signature,e.slot,e.observed_at,
			v.id::text,COALESCE(v.signature,''),v.updated_at,COALESCE(v.rule_version,''),
			COALESCE(v.grade,''),COALESCE(v.risk_index,0),COALESCE(v.risk_level,''),
			COALESCE(v.verdict,''),COALESCE(v.recommendation,''),v.evidence,v.signals,COALESCE(v.source,'')
		FROM security_actor_exit_events e
		JOIN LATERAL (
			SELECT v.*
			FROM security_radar_verdicts v
			WHERE v.network=e.network
			  AND lower(v.target)=lower(e.target)
			  AND v.module_id='final_verdict_engine'
			  AND v.signed=true
			  AND v.signature IS NOT NULL AND btrim(v.signature)<>''
			  AND (
				lower(COALESCE(v.risk_level,'')) IN ('high','critical') OR
				COALESCE(v.risk_index,0) >= 60
			  )
			  AND (
				COALESCE(v.signals->>'verified_evidence','false')='true' OR
				COALESCE(v.signals->>'real_onchain_evidence','false')='true' OR
				COALESCE(v.signals->>'real_offchain_evidence','false')='true'
			  )
			ORDER BY v.updated_at DESC,v.risk_index DESC,v.id DESC
			LIMIT 1
		) v ON true
		WHERE e.network=$1 AND lower(e.target)=lower($2)
		  AND e.evidence_state='verified'
		  AND btrim(e.actor_wallet)<>''
		  AND btrim(e.signature)<>''
		  AND e.slot>0
		ORDER BY e.observed_at ASC,e.actor_wallet ASC,e.event_kind ASC,e.signature ASC
		LIMIT $3`, network, target, securityIncidentCorpusQueryLimit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []securityIncidentCorpusCandidate{}
	for rows.Next() {
		var item securityIncidentCorpusCandidate
		if err := rows.Scan(
			&item.ActorWallet, &item.EventKind, &item.SourceRuleID, &item.EventSignature, &item.EventSlot, &item.EventObservedAt,
			&item.VerdictID, &item.VerdictSignature, &item.VerdictUpdatedAt, &item.VerdictRuleVersion,
			&item.Grade, &item.RiskIndex, &item.RiskLevel, &item.Verdict, &item.Recommendation,
			&item.EvidenceRaw, &item.SignalsRaw, &item.VerdictSource,
		); err != nil {
			return nil, err
		}
		out = append(out, item)
	}
	return out, rows.Err()
}

func securityIncidentCorpusRecordFromCandidate(network, target string, candidate securityIncidentCorpusCandidate) (SecurityIncidentCorpusRecord, error) {
	record := SecurityIncidentCorpusRecord{
		SchemaVersion: SecurityIncidentCorpusSchemaVersion,
		Network: normalizeRadarNetwork(network), Target: strings.TrimSpace(target),
		ActorWallet: strings.TrimSpace(candidate.ActorWallet), EventKind: strings.TrimSpace(candidate.EventKind),
		SourceRuleID: strings.TrimSpace(candidate.SourceRuleID), EventSignature: strings.TrimSpace(candidate.EventSignature),
		EventSlot: candidate.EventSlot, EventObservedAt: candidate.EventObservedAt.UTC(),
		VerdictID: strings.TrimSpace(candidate.VerdictID), VerdictSignature: strings.TrimSpace(candidate.VerdictSignature),
		VerdictUpdatedAt: candidate.VerdictUpdatedAt.UTC(), VerdictRuleVersion: strings.TrimSpace(candidate.VerdictRuleVersion),
		Grade: strings.TrimSpace(candidate.Grade), RiskIndex: candidate.RiskIndex,
		RiskLevel: securityIncidentMaterialRiskLevel(candidate.RiskLevel, candidate.RiskIndex),
		Verdict: strings.TrimSpace(candidate.Verdict), Recommendation: strings.TrimSpace(candidate.Recommendation),
		Evidence: []string{}, Signals: map[string]any{}, VerdictSource: strings.TrimSpace(candidate.VerdictSource),
	}
	if record.ActorWallet == "" || record.Target == "" || record.EventSignature == "" || record.EventSlot <= 0 || record.VerdictID == "" || record.VerdictSignature == "" || record.VerdictRuleVersion == "" {
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

func insertSecurityIncidentCorpusRecord(ctx context.Context, db *sql.DB, record SecurityIncidentCorpusRecord) (bool, SecurityIncidentCorpusRecord, error) {
	evidenceRaw, err := json.Marshal(record.Evidence)
	if err != nil {
		return false, record, err
	}
	signalsRaw, err := json.Marshal(record.Signals)
	if err != nil {
		return false, record, err
	}
	var id string
	var supersedes sql.NullString
	var createdAt time.Time
	err = db.QueryRowContext(ctx, `
		WITH previous AS (
			SELECT id
			FROM security_incident_corpus
			WHERE network=$3 AND target=$4 AND actor_wallet=$5 AND event_kind=$6 AND event_signature=$8
			ORDER BY verdict_updated_at DESC,created_at DESC,id DESC
			LIMIT 1
		), inserted AS (
			INSERT INTO security_incident_corpus (
				incident_key,schema_version,network,target,actor_wallet,event_kind,source_rule_id,
				event_signature,event_slot,event_observed_at,verdict_id,verdict_signature,verdict_updated_at,
				verdict_rule_version,grade,risk_index,risk_level,verdict,recommendation,evidence,signals,
				verdict_source,record_hash,supersedes_incident_id,created_at
			) VALUES (
				$1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::uuid,$12,$13,$14,$15,$16,$17,$18,$19,$20::jsonb,$21::jsonb,
				$22,$23,(SELECT id FROM previous),now()
			)
			ON CONFLICT (incident_key) DO NOTHING
			RETURNING id::text,supersedes_incident_id::text,created_at
		)
		SELECT id,supersedes_incident_id,created_at FROM inserted`,
		record.IncidentKey, record.SchemaVersion, record.Network, record.Target, record.ActorWallet, record.EventKind,
		record.SourceRuleID, record.EventSignature, record.EventSlot, record.EventObservedAt, record.VerdictID,
		record.VerdictSignature, record.VerdictUpdatedAt, record.VerdictRuleVersion, record.Grade, record.RiskIndex,
		record.RiskLevel, record.Verdict, record.Recommendation, string(evidenceRaw), string(signalsRaw),
		record.VerdictSource, record.RecordHash,
	).Scan(&id, &supersedes, &createdAt)
	if err == sql.ErrNoRows {
		err = db.QueryRowContext(ctx, `
			SELECT id::text,supersedes_incident_id::text,created_at
			FROM security_incident_corpus WHERE incident_key=$1`, record.IncidentKey).Scan(&id, &supersedes, &createdAt)
		if err != nil {
			return false, record, err
		}
		record.ID, record.SupersedesID, record.CreatedAt = id, supersedes.String, createdAt.UTC()
		return false, record, nil
	}
	if err != nil {
		return false, record, err
	}
	record.ID, record.SupersedesID, record.CreatedAt = id, supersedes.String, createdAt.UTC()
	return true, record, nil
}

func LoadSecurityIncidentCorpus(ctx context.Context, db *sql.DB, network, target, actorWallet string, limit int) (SecurityIncidentCorpusView, error) {
	network = normalizeRadarNetwork(network)
	target = strings.TrimSpace(target)
	actorWallet = strings.TrimSpace(actorWallet)
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	out := SecurityIncidentCorpusView{
		Network: network, Target: target, ActorWallet: actorWallet, Status: "no_incidents",
		Records: []SecurityIncidentCorpusRecord{}, VerdictAuthority: false, RealWorldIdentityClaim: false,
		WrongdoingClaim: false, Limitations: []string{},
	}
	if db == nil {
		out.Status = "database_unavailable"
		out.Limitations = append(out.Limitations, "Incident corpus database is unavailable.")
		return out, nil
	}

	args := []any{network}
	where := []string{"network=$1"}
	if target != "" {
		args = append(args, target)
		where = append(where, fmt.Sprintf("lower(target)=lower($%d)", len(args)))
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
	)
	return out, nil
}

func securityIncidentCorpusIncidentKey(record SecurityIncidentCorpusRecord) string {
	canonical := strings.Join([]string{
		record.SchemaVersion, record.Network, record.Target, record.ActorWallet, record.EventKind,
		record.SourceRuleID, record.EventSignature, fmt.Sprintf("%d", record.EventSlot),
		record.VerdictID, record.VerdictSignature, record.VerdictUpdatedAt.UTC().Format(time.RFC3339Nano),
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
