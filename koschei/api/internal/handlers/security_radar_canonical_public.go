package handlers

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type canonicalPublicRadarRecord struct {
	ID                  string
	Network             string
	TargetKind          string
	TargetID            string
	Grade               string
	Verdict             string
	RulesetVersion      string
	ActorRulesetVersion string
	Signed              bool
	Signature           string
	Fingerprint         string
	TriggeredRules      []map[string]any
	WatchFlags          []map[string]any
	DecisionPath        []string
	BehaviorSignals     []map[string]any
	FirstSeenAt         time.Time
	LastSeenAt          time.Time
	ScanCount           int64
}

// CanonicalSecurityRiskBadge is a read-only public projection of the persisted
// unified verdict contract. It never runs the legacy 14-arm compatibility final
// and never fabricates a numeric risk score from a categorical grade.
func (h *Handler) CanonicalSecurityRiskBadge(w http.ResponseWriter, r *http.Request) {
	target := strings.TrimSpace(firstNonEmptyString(r.URL.Query().Get("address"), r.URL.Query().Get("token")))
	if target == "" {
		writeJSON(w, http.StatusBadRequest, map[string]any{"ok": false, "error": "address parameter is required"})
		return
	}
	network := strings.TrimSpace(r.URL.Query().Get("network"))
	if network == "" {
		network = "solana-mainnet"
	}

	record, err := h.latestCanonicalPublicRadarRecord(r, network, target)
	if err != nil {
		if err == sql.ErrNoRows {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{
				"ok": false, "error": "canonical_verdict_unavailable",
				"message": "No persisted canonical Koschei verdict is available for this token yet.",
				"address": target, "grade": "-", "risk_index": nil, "risk_level": "unknown", "signed": false,
			})
			return
		}
		if isMissingRelation(err) {
			writeJSON(w, http.StatusServiceUnavailable, map[string]any{"ok": false, "error": "canonical_schema_pending", "address": target, "signed": false})
			return
		}
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Canonical Radar verdict unavailable")
		return
	}

	writeJSON(w, http.StatusOK, canonicalPublicBadgeMap(record))
}

// CanonicalSecurityRadarFeed exposes one latest signed canonical token verdict
// per target. Legacy risk_index/risk_level fields remain nullable compatibility
// fields because the canonical decision contract is categorical by design.
func (h *Handler) CanonicalSecurityRadarFeed(w http.ResponseWriter, r *http.Request) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		writeAPIError(w, http.StatusServiceUnavailable, APICodeServiceUnavailable, "Canonical Radar database unavailable")
		return
	}

	rows, err := db.QueryContext(r.Context(), `
		WITH latest AS (
			SELECT DISTINCT ON (lower(target_id))
				id::text, network, target_kind, target_id, grade, verdict,
				ruleset_version, actor_ruleset_version, signed, COALESCE(signature,''), fingerprint,
				triggered_rules, watch_flags, decision_path, behavior_signals,
				first_seen_at, last_seen_at, scan_count
			FROM security_unified_radar_verdicts
			WHERE target_kind='token'
			  AND signed=true
			  AND signature IS NOT NULL
			  AND btrim(signature)<>''
			ORDER BY lower(target_id), last_seen_at DESC, id DESC
		)
		SELECT id, network, target_kind, target_id, grade, verdict,
		       ruleset_version, actor_ruleset_version, signed, signature, fingerprint,
		       triggered_rules, watch_flags, decision_path, behavior_signals,
		       first_seen_at, last_seen_at, scan_count
		FROM latest
		ORDER BY last_seen_at DESC, id DESC
		LIMIT 100`)
	if err != nil {
		if isMissingRelation(err) {
			writeJSON(w, http.StatusOK, map[string]any{"ok": true, "source": "canonical_schema_pending", "items": []any{}, "canonical_authority": "security_unified_radar_verdicts"})
			return
		}
		writeAPIError(w, http.StatusInternalServerError, APICodeIntegrationError, "Canonical Radar feed unavailable")
		return
	}
	defer rows.Close()

	items := []map[string]any{}
	for rows.Next() {
		record, scanErr := scanCanonicalPublicRadarRecord(rows)
		if scanErr != nil {
			writeAPIError(w, http.StatusInternalServerError, APICodeIntegrationError, "Canonical Radar feed decode failed")
			return
		}
		items = append(items, canonicalPublicFeedMap(record))
	}
	if err := rows.Err(); err != nil {
		writeAPIError(w, http.StatusInternalServerError, APICodeIntegrationError, "Canonical Radar feed unavailable")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"source": "koschei_unified_radar",
		"canonical_authority": "security_unified_radar_verdicts",
		"decision_contract": "categorical_grade_no_numeric_risk",
		"items": items,
		"raw_item_count": len(items),
		"deduped_item_count": len(items),
		"stream": h.securityRadarStreamStats(r.Context()),
		"timeline": h.securityRadarStreamTimeline(r.Context(), 14),
	})
}

func (h *Handler) latestCanonicalPublicRadarRecord(r *http.Request, network, target string) (canonicalPublicRadarRecord, error) {
	db := h.DBRead
	if db == nil {
		db = h.DB
	}
	if db == nil {
		return canonicalPublicRadarRecord{}, sql.ErrConnDone
	}
	row := db.QueryRowContext(r.Context(), `
		SELECT id::text, network, target_kind, target_id, grade, verdict,
		       ruleset_version, actor_ruleset_version, signed, COALESCE(signature,''), fingerprint,
		       triggered_rules, watch_flags, decision_path, behavior_signals,
		       first_seen_at, last_seen_at, scan_count
		FROM security_unified_radar_verdicts
		WHERE network=$1
		  AND target_kind='token'
		  AND lower(target_id)=lower($2)
		  AND signed=true
		  AND signature IS NOT NULL
		  AND btrim(signature)<>''
		ORDER BY last_seen_at DESC, id DESC
		LIMIT 1`, network, target)
	return scanCanonicalPublicRadarRecord(row)
}

type canonicalPublicRadarScanner interface {
	Scan(dest ...any) error
}

func scanCanonicalPublicRadarRecord(scanner canonicalPublicRadarScanner) (canonicalPublicRadarRecord, error) {
	var record canonicalPublicRadarRecord
	var triggeredRaw, watchRaw, decisionRaw, behaviorRaw []byte
	err := scanner.Scan(
		&record.ID, &record.Network, &record.TargetKind, &record.TargetID, &record.Grade, &record.Verdict,
		&record.RulesetVersion, &record.ActorRulesetVersion, &record.Signed, &record.Signature, &record.Fingerprint,
		&triggeredRaw, &watchRaw, &decisionRaw, &behaviorRaw,
		&record.FirstSeenAt, &record.LastSeenAt, &record.ScanCount,
	)
	if err != nil {
		return canonicalPublicRadarRecord{}, err
	}
	_ = json.Unmarshal(triggeredRaw, &record.TriggeredRules)
	_ = json.Unmarshal(watchRaw, &record.WatchFlags)
	_ = json.Unmarshal(decisionRaw, &record.DecisionPath)
	_ = json.Unmarshal(behaviorRaw, &record.BehaviorSignals)
	if record.TriggeredRules == nil {
		record.TriggeredRules = []map[string]any{}
	}
	if record.WatchFlags == nil {
		record.WatchFlags = []map[string]any{}
	}
	if record.DecisionPath == nil {
		record.DecisionPath = []string{}
	}
	if record.BehaviorSignals == nil {
		record.BehaviorSignals = []map[string]any{}
	}
	return record, nil
}

func canonicalPublicBadgeMap(record canonicalPublicRadarRecord) map[string]any {
	return map[string]any{
		"ok": true,
		"address": record.TargetID,
		"target": record.TargetID,
		"network": record.Network,
		"grade": record.Grade,
		"verdict": record.Verdict,
		"risk_index": nil,
		"risk_level": "categorical_grade",
		"score_model": "categorical_grade_no_numeric_risk",
		"rule_version": record.RulesetVersion,
		"actor_rule_version": record.ActorRulesetVersion,
		"signed": record.Signed,
		"signature": record.Signature,
		"fingerprint": record.Fingerprint,
		"triggered_rules": record.TriggeredRules,
		"watch_flags": record.WatchFlags,
		"decision_path": record.DecisionPath,
		"last_seen_at": record.LastSeenAt,
		"scan_count": record.ScanCount,
		"canonical_authority": "security_unified_radar_verdicts",
	}
}

func canonicalPublicFeedMap(record canonicalPublicRadarRecord) map[string]any {
	return map[string]any{
		"id": record.ID,
		"module_id": "final_verdict_engine",
		"target": record.TargetID,
		"target_type": record.TargetKind,
		"network": record.Network,
		"grade": record.Grade,
		"risk_index": nil,
		"risk_level": "categorical_grade",
		"verdict": record.Verdict,
		"rule_version": record.RulesetVersion,
		"actor_rule_version": record.ActorRulesetVersion,
		"signed": record.Signed,
		"signature": record.Signature,
		"fingerprint": record.Fingerprint,
		"created_at": record.LastSeenAt,
		"first_seen_at": record.FirstSeenAt,
		"last_seen_at": record.LastSeenAt,
		"occurrence_count": record.ScanCount,
		"scan_count": record.ScanCount,
		"triggered_rules": record.TriggeredRules,
		"watch_flags": record.WatchFlags,
		"decision_path": record.DecisionPath,
		"behavior_signals": record.BehaviorSignals,
		"signals": map[string]any{
			"canonical_authority": true,
			"canonical_store": "security_unified_radar_verdicts",
			"categorical_grade": true,
			"deterministic_signed_contract": record.Signed,
		},
		"summary": map[string]any{
			"occurrence_count": record.ScanCount,
			"first_seen_at": record.FirstSeenAt,
			"last_seen_at": record.LastSeenAt,
		},
	}
}
