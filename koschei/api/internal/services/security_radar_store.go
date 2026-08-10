package services

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

const securityRadarDefaultSource = "solana_rpc"

type SecurityRadarStore struct {
	DB *sql.DB
}

type SecurityRadarEventRecord struct {
	ModuleID      string
	Target        string
	TargetType    string
	Network       string
	Signature     string
	SourceAddress string
	EventType     string
	Slot          int64
	BlockTime     *time.Time
	Signals       map[string]any
	RawSummary    map[string]any
	Source        string
}

type SecurityRadarVerdictRecord struct {
	ID             string         `json:"id,omitempty"`
	EventID        string         `json:"event_id,omitempty"`
	ModuleID       string         `json:"module_id"`
	Target         string         `json:"target"`
	TargetType     string         `json:"target_type"`
	Network        string         `json:"network"`
	Grade          string         `json:"grade"`
	RiskIndex      int            `json:"risk_index"`
	RiskLevel      string         `json:"risk_level"`
	Verdict        string         `json:"verdict"`
	Recommendation string         `json:"recommendation"`
	Evidence       []string       `json:"evidence"`
	Signals        map[string]any `json:"signals"`
	RuleVersion    string         `json:"rule_version"`
	Signed         bool           `json:"signed"`
	Signature      string         `json:"signature"`
	Source         string         `json:"source,omitempty"`
	EventType      string         `json:"event_type,omitempty"`
	Provider       string         `json:"provider,omitempty"`
	CreatedAt      time.Time      `json:"created_at"`
}

func NewSecurityRadarStore(db *sql.DB) *SecurityRadarStore {
	return &SecurityRadarStore{DB: db}
}

func (s *SecurityRadarStore) MarkSignatureSeen(ctx context.Context, moduleID, signature, sourceAddress, network string) (bool, error) {
	if s == nil || s.DB == nil {
		return false, nil
	}
	moduleID = strings.TrimSpace(moduleID)
	signature = strings.TrimSpace(signature)
	sourceAddress = strings.TrimSpace(sourceAddress)
	network = normalizeRadarNetwork(network)
	if moduleID == "" || signature == "" {
		return false, nil
	}
	var id string
	// Production carries both the legacy (module_id, signature) unique index
	// and the newer network-scoped index. A targetless conflict handler makes
	// duplicate PumpPortal deliveries idempotent against either constraint.
	err := s.DB.QueryRowContext(ctx, `
		INSERT INTO security_radar_seen_signatures (module_id, signature, source_address, source_target, network, seen_at, created_at)
		VALUES ($1,$2,NULLIF($3,''),NULLIF($3,''),$4,now(),now())
		ON CONFLICT DO NOTHING
		RETURNING id::text`, moduleID, signature, sourceAddress, network).Scan(&id)
	if err == sql.ErrNoRows {
		return false, nil
	}
	return err == nil, err
}

func (s *SecurityRadarStore) InsertEvent(ctx context.Context, event SecurityRadarEventRecord) (string, error) {
	if s == nil || s.DB == nil {
		return "", nil
	}
	event.ModuleID = strings.TrimSpace(event.ModuleID)
	event.Target = strings.TrimSpace(event.Target)
	event.TargetType = firstSecurityRadarString(event.TargetType, "unknown")
	event.Network = normalizeRadarNetwork(event.Network)
	event.EventType = firstSecurityRadarString(event.EventType, "solana_signature")
	event.Source = firstSecurityRadarString(event.Source, securityRadarDefaultSource)
	if event.ModuleID == "" || event.Target == "" {
		return "", nil
	}
	signals, err := marshalSecurityRadarJSON(nonNilMap(event.Signals))
	if err != nil {
		return "", fmt.Errorf("encode event signals: %w", err)
	}
	rawSummary, err := marshalSecurityRadarJSON(nonNilMap(event.RawSummary))
	if err != nil {
		return "", fmt.Errorf("encode event summary: %w", err)
	}
	var id string
	err = s.DB.QueryRowContext(ctx, `
		INSERT INTO security_radar_events (module_id,target,target_type,network,signature,source_address,event_type,slot,block_time,signals,raw_summary,source,created_at,updated_at)
		VALUES ($1,$2,$3,$4,NULLIF($5,''),NULLIF($6,''),$7,NULLIF($8,0),$9,$10::jsonb,$11::jsonb,$12,now(),now())
		ON CONFLICT DO NOTHING
		RETURNING id::text`, event.ModuleID, event.Target, event.TargetType, event.Network, event.Signature, event.SourceAddress, event.EventType, event.Slot, event.BlockTime, string(signals), string(rawSummary), event.Source).Scan(&id)
	if err == sql.ErrNoRows && strings.TrimSpace(event.Signature) != "" {
		err = s.DB.QueryRowContext(ctx, `
			SELECT id::text
			FROM security_radar_events
			WHERE module_id=$1 AND signature=$2 AND source=$3
			ORDER BY created_at ASC
			LIMIT 1`, event.ModuleID, event.Signature, event.Source).Scan(&id)
	}
	return id, err
}

func (s *SecurityRadarStore) InsertVerdict(ctx context.Context, verdict SecurityRadarVerdictRecord) (string, error) {
	if s == nil || s.DB == nil {
		return "", nil
	}
	verdict.ModuleID = strings.TrimSpace(verdict.ModuleID)
	verdict.Target = strings.TrimSpace(verdict.Target)
	verdict.TargetType = firstSecurityRadarString(verdict.TargetType, "unknown")
	verdict.Network = normalizeRadarNetwork(verdict.Network)
	verdict.RuleVersion = firstSecurityRadarString(verdict.RuleVersion, SecurityRadarRuleVersion)
	verdict.Source = firstSecurityRadarString(verdict.Source, securityRadarDefaultSource)
	if verdict.Provider == "" {
		verdict.Provider = verdict.Source
	}
	if verdict.ModuleID == "" || verdict.Target == "" {
		return "", nil
	}

	// Structural score layer: harvest holder/authority facts from every
	// verdict, and floor final_verdict_engine scores to the cached
	// structural baseline so event-evidence gaps can't flip a risky token
	// green. Both calls are best-effort and never block the insert.
	verdict.Signals = nonNilMap(verdict.Signals)
	s.captureStructuralSignals(ctx, verdict)
	s.applyStructuralFloor(ctx, &verdict)

	signals := nonNilMap(verdict.Signals)
	if verdict.Source == "arvis_stream" {
		if streamEventID, _ := signals["source_stream_event_id"].(string); strings.TrimSpace(streamEventID) != "" {
			verdict.Signature = arvisStreamScopedVerdictSignature(verdict.Signature, verdict.ModuleID, streamEventID)
			signals["stream_scoped_signature"] = true
		}
	}
	if shouldApplySBX1HiddenSignals(verdict) {
		hidden := buildSBX1HiddenSignalPack(ctx, verdict)
		applyHiddenRiskAdjustment(&verdict, hidden.RiskAdjustment)
		signals["sbx1_hidden_signal_pack"] = hidden.Signals
		signals["sbx1_hidden_risk_adjustment"] = hidden.RiskAdjustment
		signals["sbx1_hidden_customer_surface"] = false
	}
	evidence, err := marshalSecurityRadarJSON(nonNilEvidence(verdict.Evidence))
	if err != nil {
		return "", fmt.Errorf("encode verdict evidence: %w", err)
	}
	if verdict.EventType != "" {
		signals["event_type"] = verdict.EventType
	}
	if verdict.Provider != "" {
		signals["provider"] = verdict.Provider
	}
	signalsRaw, err := marshalSecurityRadarJSON(signals)
	if err != nil {
		return "", fmt.Errorf("encode verdict signals: %w", err)
	}
	var id string
	err = s.DB.QueryRowContext(ctx, `
		INSERT INTO security_radar_verdicts (event_id,module_id,target,target_type,network,grade,risk_index,risk_level,verdict,recommendation,evidence,signals,rule_version,signed,signature,source,created_at,updated_at)
		VALUES (NULLIF($1,'')::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11::jsonb,$12::jsonb,$13,$14,NULLIF($15,''),$16,now(),now())
		ON CONFLICT (signature,module_id) WHERE signature IS NOT NULL DO UPDATE SET
			event_id=COALESCE(EXCLUDED.event_id, security_radar_verdicts.event_id),
			target=EXCLUDED.target,
			target_type=EXCLUDED.target_type,
			network=EXCLUDED.network,
			grade=EXCLUDED.grade,
			risk_index=EXCLUDED.risk_index,
			risk_level=EXCLUDED.risk_level,
			verdict=EXCLUDED.verdict,
			recommendation=EXCLUDED.recommendation,
			evidence=EXCLUDED.evidence,
			signals=EXCLUDED.signals,
			rule_version=EXCLUDED.rule_version,
			signed=EXCLUDED.signed,
			source=EXCLUDED.source,
			updated_at=now()
		RETURNING id::text`, verdict.EventID, verdict.ModuleID, verdict.Target, verdict.TargetType, verdict.Network, verdict.Grade, verdict.RiskIndex, verdict.RiskLevel, verdict.Verdict, verdict.Recommendation, string(evidence), string(signalsRaw), verdict.RuleVersion, verdict.Signed, verdict.Signature, verdict.Source).Scan(&id)
	if err != nil && strings.TrimSpace(verdict.EventID) != "" {
		_, _ = s.DB.ExecContext(ctx, `
			DELETE FROM security_radar_events e
			WHERE e.id=$1::uuid
			  AND NOT EXISTS (SELECT 1 FROM security_radar_verdicts v WHERE v.event_id=e.id)
		`, verdict.EventID)
	}
	return id, err
}

func (s *SecurityRadarStore) LatestVerdicts(ctx context.Context, limit int) ([]SecurityRadarVerdictRecord, error) {
	if s == nil || s.DB == nil {
		return []SecurityRadarVerdictRecord{}, nil
	}
	if limit <= 0 || limit > 100 {
		limit = 50
	}

	items, err := s.latestVerdictsWindow(ctx, limit, true)
	if err != nil || len(items) > 0 {
		return items, err
	}
	return s.latestVerdictsWindow(ctx, limit, false)
}

func (s *SecurityRadarStore) latestVerdictsWindow(ctx context.Context, limit int, recentOnly bool) ([]SecurityRadarVerdictRecord, error) {
	windowFilter := ""
	if recentOnly {
		windowFilter = "AND v.created_at >= now() - interval '24 hours'"
	}

	query := `
		WITH representatives AS (
			SELECT DISTINCT ON (v.target)
				v.id::text AS id,
				COALESCE(v.event_id::text,'') AS event_id,
				v.module_id,
				v.target,
				v.target_type,
				v.network,
				v.grade,
				v.risk_index,
				v.risk_level,
				v.verdict,
				v.recommendation,
				v.evidence,
				v.signals,
				v.rule_version,
				v.signed,
				COALESCE(v.signature,'') AS signature,
				COALESCE(v.source,'') AS source,
				COALESCE(e.event_type,'') AS event_type,
				v.created_at
			FROM security_radar_verdicts v
			LEFT JOIN security_radar_events e ON e.id = v.event_id
			WHERE v.module_id = 'final_verdict_engine'
			  AND v.signed = true
			  AND v.signature IS NOT NULL
			  AND btrim(v.signature) <> ''
			  AND btrim(v.target) <> ''
			  AND NOT (v.target = ANY (` + securityRadarPublicFeedExcludedMintsSQL + `))
			  AND (
				COALESCE(v.signals->>'verified_evidence','false') = 'true'
				OR COALESCE(v.signals->>'real_onchain_evidence','false') = 'true'
				OR COALESCE(v.signals->>'real_offchain_evidence','false') = 'true'
			  )
			  ` + windowFilter + `
			ORDER BY v.target, v.risk_index DESC, v.created_at DESC, v.id DESC
		)
		SELECT id, event_id, module_id, target, target_type, network, grade, risk_index, risk_level, verdict, recommendation, evidence, signals, rule_version, signed, signature, source, event_type, created_at
		FROM representatives
		ORDER BY risk_index DESC, created_at DESC
		LIMIT $1`

	rows, err := s.DB.QueryContext(ctx, query, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	items := []SecurityRadarVerdictRecord{}
	for rows.Next() {
		var item SecurityRadarVerdictRecord
		var evidenceRaw, signalsRaw []byte
		if err := rows.Scan(&item.ID, &item.EventID, &item.ModuleID, &item.Target, &item.TargetType, &item.Network, &item.Grade, &item.RiskIndex, &item.RiskLevel, &item.Verdict, &item.Recommendation, &evidenceRaw, &signalsRaw, &item.RuleVersion, &item.Signed, &item.Signature, &item.Source, &item.EventType, &item.CreatedAt); err != nil {
			return nil, err
		}
		_ = json.Unmarshal(evidenceRaw, &item.Evidence)
		_ = json.Unmarshal(signalsRaw, &item.Signals)
		if item.Evidence == nil {
			item.Evidence = []string{}
		}
		if item.Signals == nil {
			item.Signals = map[string]any{}
		}
		if provider, ok := item.Signals["provider"].(string); ok && provider != "" {
			item.Provider = provider
		} else if item.Source != "" {
			item.Provider = item.Source
		}
		items = append(items, item)
	}
	return items, rows.Err()
}

func normalizeRadarNetwork(network string) string {
	if strings.TrimSpace(network) == "" {
		return "solana-mainnet"
	}
	return strings.TrimSpace(network)
}

func firstSecurityRadarString(value, fallback string) string {
	if strings.TrimSpace(value) != "" {
		return strings.TrimSpace(value)
	}
	return fallback
}

func nonNilMap(in map[string]any) map[string]any {
	if in == nil {
		return map[string]any{}
	}
	return in
}

func nonNilEvidence(in []string) []string {
	if in == nil {
		return []string{}
	}
	return in
}

func (s *SecurityRadarStore) CaptureHolderSnapshots(ctx context.Context, target, network string, holder HolderIntelligence) error {
	if s == nil || s.DB == nil || !holder.Available {
		return nil
	}
	target = strings.TrimSpace(target)
	network = normalizeRadarNetwork(network)
	if target == "" {
		return nil
	}
	scannedAt := time.Now().UTC()
	scanID := fmt.Sprintf("%s|%s|%d", target, network, scannedAt.UnixNano())
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	riskRank := 0
	for _, row := range holder.Rows {
		owner := strings.TrimSpace(row.OwnerWallet)
		if owner == "" || !row.OwnerResolved || !row.RiskBearing || row.ExcludedFromHolderRisk {
			continue
		}
		riskRank++
		if riskRank > 5 {
			break
		}
		percentage := row.CirculatingPercentage
		if percentage <= 0 {
			percentage = row.RawPercentage
		}
		if _, err := tx.ExecContext(ctx, `
            INSERT INTO security_radar_holder_snapshots
                (scan_id,target,network,owner_wallet,holder_rank,balance,percentage,scanned_at,created_at)
            VALUES ($1,$2,$3,$4,$5,$6,$7,$8,now())
            ON CONFLICT (scan_id,owner_wallet) DO UPDATE SET
                holder_rank=EXCLUDED.holder_rank,
                balance=EXCLUDED.balance,
                percentage=EXCLUDED.percentage,
                scanned_at=EXCLUDED.scanned_at`,
			scanID, target, network, owner, riskRank, row.Balance, percentage, scannedAt); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *SecurityRadarStore) RepeatDominantHolders(ctx context.Context, holder HolderIntelligence, currentMint string, windowDays int) ([]RepeatDominantHolderEvidence, error) {
	if s == nil || s.DB == nil || !holder.Available {
		return []RepeatDominantHolderEvidence{}, nil
	}
	if windowDays <= 0 {
		windowDays = RepeatDominantObservationDays
	}
	out := []RepeatDominantHolderEvidence{}
	checked := 0
	for _, row := range holder.Rows {
		owner := strings.TrimSpace(row.OwnerWallet)
		if owner == "" || !row.OwnerResolved || !row.RiskBearing || row.ExcludedFromHolderRisk {
			continue
		}
		checked++
		if checked > 5 {
			break
		}
		matches, err := s.repeatDominantHolderMatches(ctx, owner, windowDays)
		if err != nil {
			return nil, err
		}
		qualifying := make([]RepeatDominantHolderMatch, 0, len(matches))
		for _, match := range matches {
			if match.Percentage >= 20 {
				qualifying = append(qualifying, match)
			}
		}
		if len(qualifying) < 2 {
			continue
		}
		currentPercentage := row.CirculatingPercentage
		if currentPercentage <= 0 {
			currentPercentage = row.RawPercentage
		}
		riskWeight := RepeatDominantRiskWeight(currentPercentage, len(qualifying))
		if riskWeight == 0 {
			continue
		}
		evidence := RepeatDominantHolderEvidence{
			OwnerWallet:       owner,
			CurrentMint:       strings.TrimSpace(currentMint),
			CurrentPercentage: currentPercentage,
			TokenCount:        len(qualifying),
			ObservationDays:   windowDays,
			ObservationWindow: fmt.Sprintf("son %d gün Koschei gözlemi", windowDays),
			RiskWeight:        riskWeight,
			Matches:           qualifying,
		}
		evidence.EvidenceLine = RepeatDominantEvidenceLine(owner, qualifying, windowDays)
		out = append(out, evidence)
	}
	return out, nil
}

func (s *SecurityRadarStore) repeatDominantHolderMatches(ctx context.Context, owner string, windowDays int) ([]RepeatDominantHolderMatch, error) {
	rows, err := s.DB.QueryContext(ctx, `
        WITH latest AS (
            SELECT DISTINCT ON (target)
                target, percentage, holder_rank, scanned_at
            FROM security_radar_holder_snapshots
            WHERE owner_wallet=$1
              AND scanned_at >= now() - make_interval(days => $2)
            ORDER BY target, scanned_at DESC, id DESC
        )
        SELECT target, percentage, holder_rank, scanned_at
        FROM latest
        ORDER BY percentage DESC, scanned_at DESC`, owner, windowDays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RepeatDominantHolderMatch{}
	for rows.Next() {
		var item RepeatDominantHolderMatch
		var scannedAt time.Time
		if err := rows.Scan(&item.Mint, &item.Percentage, &item.Rank, &scannedAt); err != nil {
			return nil, err
		}
		item.ScannedAt = scannedAt.UTC().Format(time.RFC3339)
		out = append(out, item)
	}
	return out, rows.Err()
}

func (s *SecurityRadarStore) RepeatDominantHolderMatchesExceptMint(ctx context.Context, owner, currentMint string, windowDays int) ([]RepeatDominantHolderMatch, error) {
	owner = strings.TrimSpace(owner)
	currentMint = strings.TrimSpace(currentMint)
	if windowDays <= 0 {
		windowDays = RepeatDominantObservationDays
	}
	if s == nil || s.DB == nil {
		return nil, fmt.Errorf("security radar database is unavailable")
	}
	if owner == "" {
		return nil, fmt.Errorf("owner wallet is required")
	}
	rows, err := s.DB.QueryContext(ctx, `
        WITH latest AS (
            SELECT DISTINCT ON (target)
                target, percentage, holder_rank, scanned_at
            FROM security_radar_holder_snapshots
            WHERE owner_wallet=$1
              AND target <> $2
              AND holder_rank BETWEEN 1 AND 5
              AND scanned_at >= now() - make_interval(days => $3)
            ORDER BY target, scanned_at DESC, id DESC
        )
        SELECT target, percentage, holder_rank, scanned_at
        FROM latest
        ORDER BY percentage DESC, scanned_at DESC`, owner, currentMint, windowDays)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []RepeatDominantHolderMatch{}
	for rows.Next() {
		var item RepeatDominantHolderMatch
		var scannedAt time.Time
		if err := rows.Scan(&item.Mint, &item.Percentage, &item.Rank, &scannedAt); err != nil {
			return nil, err
		}
		item.ScannedAt = scannedAt.UTC().Format(time.RFC3339)
		out = append(out, item)
	}
	return out, rows.Err()
}
