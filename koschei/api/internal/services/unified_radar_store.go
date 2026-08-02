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

type UnifiedRadarVerdictHistoryRecord struct {
	ID                  string                `json:"id"`
	Network             string                `json:"network"`
	TargetKind          string                `json:"target_kind"`
	TargetID            string                `json:"target_id"`
	Grade               string                `json:"grade"`
	Verdict             string                `json:"verdict"`
	RulesetVersion      string                `json:"ruleset_version"`
	ActorRulesetVersion string                `json:"actor_ruleset_version"`
	Signed              bool                  `json:"signed"`
	Signature           string                `json:"signature,omitempty"`
	Fingerprint         string                `json:"fingerprint"`
	TriggeredRules      []ActorDefenseRuleHit `json:"triggered_rules"`
	WatchFlags          []ActorDefenseRuleHit `json:"watch_flags"`
	DecisionPath        []string              `json:"decision_path"`
	BehaviorSignals     []UnifiedRadarSignal  `json:"behavior_signals"`
	FirstSeenAt         time.Time             `json:"first_seen_at"`
	LastSeenAt          time.Time             `json:"last_seen_at"`
	ScanCount           int64                 `json:"scan_count"`
}

type UnifiedRadarVerdictStore struct {
	DB *sql.DB
}

func NewUnifiedRadarVerdictStore(db *sql.DB) *UnifiedRadarVerdictStore {
	return &UnifiedRadarVerdictStore{DB: db}
}

func (s *UnifiedRadarVerdictStore) Persist(ctx context.Context, network, targetKind, targetID string, verdict UnifiedRadarVerdict, behavior UnifiedRadarBehaviorReport) (UnifiedRadarVerdictHistoryRecord, error) {
	if s == nil || s.DB == nil {
		return UnifiedRadarVerdictHistoryRecord{}, fmt.Errorf("unified radar verdict database is unavailable")
	}
	network = normalizeRadarNetwork(network)
	targetKind = strings.TrimSpace(targetKind)
	targetID = strings.TrimSpace(targetID)
	if targetKind == "" || targetID == "" {
		return UnifiedRadarVerdictHistoryRecord{}, fmt.Errorf("unified radar target is required")
	}
	verdict = FinalizeUnifiedRadarVerdictContract(targetID, verdict)
	fingerprint, err := UnifiedRadarVerdictFingerprint(network, targetKind, targetID, verdict, behavior)
	if err != nil {
		return UnifiedRadarVerdictHistoryRecord{}, err
	}
	triggered, err := json.Marshal(nonNilActorRuleHits(verdict.TriggeredRules))
	if err != nil {
		return UnifiedRadarVerdictHistoryRecord{}, fmt.Errorf("encode unified triggered rules: %w", err)
	}
	watch, err := json.Marshal(nonNilActorRuleHits(verdict.WatchFlags))
	if err != nil {
		return UnifiedRadarVerdictHistoryRecord{}, fmt.Errorf("encode unified watch flags: %w", err)
	}
	decision, err := json.Marshal(nonNilStrings(verdict.DecisionPath))
	if err != nil {
		return UnifiedRadarVerdictHistoryRecord{}, fmt.Errorf("encode unified decision path: %w", err)
	}
	signals, err := json.Marshal(nonNilUnifiedSignals(behavior.Signals))
	if err != nil {
		return UnifiedRadarVerdictHistoryRecord{}, fmt.Errorf("encode unified behavior signals: %w", err)
	}
	generatedAt := verdict.GeneratedAt.UTC()
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	var record UnifiedRadarVerdictHistoryRecord
	var triggeredRaw, watchRaw, decisionRaw, signalsRaw []byte
	err = s.DB.QueryRowContext(ctx, `
		INSERT INTO security_unified_radar_verdicts (
			network,target_kind,target_id,grade,verdict,ruleset_version,actor_ruleset_version,
			signed,signature,fingerprint,triggered_rules,watch_flags,decision_path,behavior_signals,
			first_seen_at,last_seen_at,scan_count,created_at,updated_at
		)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,NULLIF($9,''),$10,$11::jsonb,$12::jsonb,$13::jsonb,$14::jsonb,$15,$15,1,now(),now())
		ON CONFLICT (fingerprint)
		DO UPDATE SET
			last_seen_at=GREATEST(security_unified_radar_verdicts.last_seen_at,EXCLUDED.last_seen_at),
			scan_count=security_unified_radar_verdicts.scan_count+1,
			signed=security_unified_radar_verdicts.signed OR EXCLUDED.signed,
			signature=COALESCE(EXCLUDED.signature,security_unified_radar_verdicts.signature),
			triggered_rules=EXCLUDED.triggered_rules,
			watch_flags=EXCLUDED.watch_flags,
			decision_path=EXCLUDED.decision_path,
			behavior_signals=EXCLUDED.behavior_signals,
			updated_at=now()
		RETURNING id::text,network,target_kind,target_id,grade,verdict,ruleset_version,
		          actor_ruleset_version,signed,COALESCE(signature,''),fingerprint,
		          triggered_rules,watch_flags,decision_path,behavior_signals,
		          first_seen_at,last_seen_at,scan_count`,
		network, targetKind, targetID, normalizeUnifiedGrade(verdict.Grade), strings.TrimSpace(verdict.Verdict),
		strings.TrimSpace(verdict.RulesetVersion), strings.TrimSpace(verdict.ActorRuleset), verdict.Signed,
		strings.TrimSpace(verdict.Signature), fingerprint, string(triggered), string(watch), string(decision),
		string(signals), generatedAt,
	).Scan(
		&record.ID, &record.Network, &record.TargetKind, &record.TargetID, &record.Grade,
		&record.Verdict, &record.RulesetVersion, &record.ActorRulesetVersion, &record.Signed,
		&record.Signature, &record.Fingerprint, &triggeredRaw, &watchRaw, &decisionRaw,
		&signalsRaw, &record.FirstSeenAt, &record.LastSeenAt, &record.ScanCount,
	)
	if err != nil {
		return UnifiedRadarVerdictHistoryRecord{}, err
	}
	_ = json.Unmarshal(triggeredRaw, &record.TriggeredRules)
	_ = json.Unmarshal(watchRaw, &record.WatchFlags)
	_ = json.Unmarshal(decisionRaw, &record.DecisionPath)
	_ = json.Unmarshal(signalsRaw, &record.BehaviorSignals)
	record.TriggeredRules = nonNilActorRuleHits(record.TriggeredRules)
	record.WatchFlags = nonNilActorRuleHits(record.WatchFlags)
	record.DecisionPath = nonNilStrings(record.DecisionPath)
	record.BehaviorSignals = nonNilUnifiedSignals(record.BehaviorSignals)
	return record, nil
}

func (s *UnifiedRadarVerdictStore) History(ctx context.Context, network, targetKind, targetID string, limit int) ([]UnifiedRadarVerdictHistoryRecord, error) {
	if s == nil || s.DB == nil {
		return nil, fmt.Errorf("unified radar verdict database is unavailable")
	}
	if limit <= 0 || limit > 100 {
		limit = 20
	}
	rows, err := s.DB.QueryContext(ctx, `
		SELECT id::text,network,target_kind,target_id,grade,verdict,ruleset_version,
		       actor_ruleset_version,signed,COALESCE(signature,''),fingerprint,
		       triggered_rules,watch_flags,decision_path,behavior_signals,
		       first_seen_at,last_seen_at,scan_count
		FROM security_unified_radar_verdicts
		WHERE network=$1 AND target_kind=$2 AND target_id=$3
		ORDER BY last_seen_at DESC,id DESC
		LIMIT $4`, normalizeRadarNetwork(network), strings.TrimSpace(targetKind), strings.TrimSpace(targetID), limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []UnifiedRadarVerdictHistoryRecord{}
	for rows.Next() {
		var record UnifiedRadarVerdictHistoryRecord
		var triggeredRaw, watchRaw, decisionRaw, signalsRaw []byte
		if err := rows.Scan(
			&record.ID, &record.Network, &record.TargetKind, &record.TargetID, &record.Grade,
			&record.Verdict, &record.RulesetVersion, &record.ActorRulesetVersion, &record.Signed,
			&record.Signature, &record.Fingerprint, &triggeredRaw, &watchRaw, &decisionRaw,
			&signalsRaw, &record.FirstSeenAt, &record.LastSeenAt, &record.ScanCount,
		); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(triggeredRaw, &record.TriggeredRules)
		_ = json.Unmarshal(watchRaw, &record.WatchFlags)
		_ = json.Unmarshal(decisionRaw, &record.DecisionPath)
		_ = json.Unmarshal(signalsRaw, &record.BehaviorSignals)
		record.TriggeredRules = nonNilActorRuleHits(record.TriggeredRules)
		record.WatchFlags = nonNilActorRuleHits(record.WatchFlags)
		record.DecisionPath = nonNilStrings(record.DecisionPath)
		record.BehaviorSignals = nonNilUnifiedSignals(record.BehaviorSignals)
		out = append(out, record)
	}
	return out, rows.Err()
}

func UnifiedRadarVerdictFingerprint(network, targetKind, targetID string, verdict UnifiedRadarVerdict, behavior UnifiedRadarBehaviorReport) (string, error) {
	payload := struct {
		Network        string                `json:"network"`
		TargetKind     string                `json:"target_kind"`
		TargetID       string                `json:"target_id"`
		Grade          string                `json:"grade"`
		Verdict        string                `json:"verdict"`
		Ruleset        string                `json:"ruleset"`
		ActorRuleset   string                `json:"actor_ruleset"`
		TriggeredRules []ActorDefenseRuleHit `json:"triggered_rules"`
		WatchFlags     []ActorDefenseRuleHit `json:"watch_flags"`
		Behavior       []UnifiedRadarSignal  `json:"behavior"`
	}{
		Network: normalizeRadarNetwork(network), TargetKind: strings.TrimSpace(targetKind),
		TargetID: strings.TrimSpace(targetID), Grade: normalizeUnifiedGrade(verdict.Grade),
		Verdict: strings.TrimSpace(verdict.Verdict), Ruleset: strings.TrimSpace(verdict.RulesetVersion),
		ActorRuleset:   strings.TrimSpace(verdict.ActorRuleset),
		TriggeredRules: nonNilActorRuleHits(verdict.TriggeredRules),
		WatchFlags:     nonNilActorRuleHits(verdict.WatchFlags), Behavior: nonNilUnifiedSignals(behavior.Signals),
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("encode unified verdict fingerprint: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "koschei-unified-state:" + hex.EncodeToString(sum[:]), nil
}

func normalizeUnifiedGrade(value string) string {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "A", "B", "C", "D", "E", "F":
		return strings.ToUpper(strings.TrimSpace(value))
	default:
		return "-"
	}
}

func nonNilActorRuleHits(input []ActorDefenseRuleHit) []ActorDefenseRuleHit {
	if input == nil {
		return []ActorDefenseRuleHit{}
	}
	return input
}

func nonNilUnifiedSignals(input []UnifiedRadarSignal) []UnifiedRadarSignal {
	if input == nil {
		return []UnifiedRadarSignal{}
	}
	return input
}

func nonNilStrings(input []string) []string {
	if input == nil {
		return []string{}
	}
	return input
}
