package services

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
)

const (
	structuralSignalMaxAge = 7 * 24 * time.Hour
	structuralCacheTimeout = 1200 * time.Millisecond
)

type tokenStructuralSignals struct {
	LargestHolderPct          int
	Top10HolderPct            int
	HasHolderData             bool
	MintAuthorityPresent      bool
	FreezeAuthorityPresent    bool
	HasAuthorityData          bool
	TokenSupply               float64
	HasSupplyData             bool
	HolderObservedAt          *time.Time
	AuthorityObservedAt       *time.Time
	SupplyObservedAt          *time.Time
	LaunchForensicsRisk       int
	LaunchForensicsObservedAt *time.Time
}

func (t tokenStructuralSignals) structuralFloor(now time.Time) (int, time.Time) {
	floor := 0
	var observedAt time.Time

	if t.HasHolderData && structuralObservationFresh(now, t.HolderObservedAt) {
		if value := 5 + concentrationRisk(t.LargestHolderPct, t.Top10HolderPct); value > floor {
			floor = value
			observedAt = t.HolderObservedAt.UTC()
		}
	}
	if t.HasAuthorityData && structuralObservationFresh(now, t.AuthorityObservedAt) {
		value := 5
		if t.MintAuthorityPresent {
			value += 38
		}
		if t.FreezeAuthorityPresent {
			value += 38
		}
		if value > floor {
			floor = value
			observedAt = t.AuthorityObservedAt.UTC()
		}
	}
	if t.LaunchForensicsRisk > 0 && structuralObservationFresh(now, t.LaunchForensicsObservedAt) {
		if t.LaunchForensicsRisk > floor {
			floor = t.LaunchForensicsRisk
			observedAt = t.LaunchForensicsObservedAt.UTC()
		}
	}
	if floor <= 0 {
		return 0, time.Time{}
	}
	return clampRisk(floor), observedAt
}

func structuralObservationFresh(now time.Time, observedAt *time.Time) bool {
	if observedAt == nil || observedAt.IsZero() {
		return false
	}
	age := now.Sub(observedAt.UTC())
	return age <= structuralSignalMaxAge
}

// captureStructuralSignals stores only signed, evidence-backed structural
// observations. Zero-valued holder placeholders are ignored so a transient
// RPC gap cannot erase a previously verified concentration observation.
func (s *SecurityRadarStore) captureStructuralSignals(ctx context.Context, verdict SecurityRadarVerdictRecord) {
	if s == nil || s.DB == nil || verdict.Signals == nil || !verdict.Signed {
		return
	}
	target := strings.TrimSpace(verdict.Target)
	if target == "" || IsSecurityRadarInfraTarget(target) || !structuralSignalsVerified(verdict.Signals) {
		return
	}
	network := normalizeRadarNetwork(verdict.Network)

	largest, hasLargest := structuralSignalInt(verdict.Signals, "largest_holder_percentage")
	top10, hasTop10 := structuralSignalInt(verdict.Signals, "top_10_holder_percentage")
	largestAccounts, hasLargestAccounts := structuralSignalInt(verdict.Signals, "largest_accounts")
	hasHolder := hasLargest && hasTop10 && (largest > 0 || top10 > 0 || (hasLargestAccounts && largestAccounts > 0))
	largest = clampStructuralPercent(largest)
	top10 = clampStructuralPercent(top10)

	mintAuth, hasMintAuth := structuralSignalBool(verdict.Signals, "mint_authority_present")
	freezeAuth, hasFreezeAuth := structuralSignalBool(verdict.Signals, "freeze_authority_present")
	isTokenMint, _ := structuralSignalBool(verdict.Signals, "is_token_mint")
	hasAuthority := hasMintAuth && hasFreezeAuth && (verdict.ModuleID == ModuleTokenAuthorityScanner || isTokenMint)

	tokenSupply, hasTokenSupply := structuralSignalFloat(verdict.Signals, "token_supply")
	hasSupply := hasTokenSupply && tokenSupply >= 0 && verdict.ModuleID == ModuleHolderConcentration

	if !hasHolder && !hasAuthority && !hasSupply {
		return
	}

	cacheCtx, cancel := context.WithTimeout(ctx, structuralCacheTimeout)
	defer cancel()
	_, _ = s.DB.ExecContext(cacheCtx, `
		INSERT INTO token_structural_signals
			(target, network, largest_holder_pct, top10_holder_pct, has_holder_data,
			 mint_authority_present, freeze_authority_present, has_authority_data,
			 token_supply, has_supply_data,
			 holder_observed_at, authority_observed_at, supply_observed_at, observed_at, updated_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,
			CASE WHEN $5 THEN now() ELSE NULL END,
			CASE WHEN $8 THEN now() ELSE NULL END,
			CASE WHEN $10 THEN now() ELSE NULL END,
			now(),now())
		ON CONFLICT (target, network) DO UPDATE SET
			largest_holder_pct = CASE WHEN EXCLUDED.has_holder_data THEN EXCLUDED.largest_holder_pct ELSE token_structural_signals.largest_holder_pct END,
			top10_holder_pct = CASE WHEN EXCLUDED.has_holder_data THEN EXCLUDED.top10_holder_pct ELSE token_structural_signals.top10_holder_pct END,
			has_holder_data = token_structural_signals.has_holder_data OR EXCLUDED.has_holder_data,
			holder_observed_at = CASE WHEN EXCLUDED.has_holder_data THEN EXCLUDED.holder_observed_at ELSE token_structural_signals.holder_observed_at END,
			mint_authority_present = CASE WHEN EXCLUDED.has_authority_data THEN EXCLUDED.mint_authority_present ELSE token_structural_signals.mint_authority_present END,
			freeze_authority_present = CASE WHEN EXCLUDED.has_authority_data THEN EXCLUDED.freeze_authority_present ELSE token_structural_signals.freeze_authority_present END,
			has_authority_data = token_structural_signals.has_authority_data OR EXCLUDED.has_authority_data,
			authority_observed_at = CASE WHEN EXCLUDED.has_authority_data THEN EXCLUDED.authority_observed_at ELSE token_structural_signals.authority_observed_at END,
			token_supply = CASE WHEN EXCLUDED.has_supply_data THEN EXCLUDED.token_supply ELSE token_structural_signals.token_supply END,
			has_supply_data = token_structural_signals.has_supply_data OR EXCLUDED.has_supply_data,
			supply_observed_at = CASE WHEN EXCLUDED.has_supply_data THEN EXCLUDED.supply_observed_at ELSE token_structural_signals.supply_observed_at END,
			observed_at = GREATEST(
				COALESCE(CASE WHEN EXCLUDED.has_holder_data THEN EXCLUDED.holder_observed_at END, '-infinity'::timestamptz),
				COALESCE(CASE WHEN EXCLUDED.has_authority_data THEN EXCLUDED.authority_observed_at END, '-infinity'::timestamptz),
				COALESCE(CASE WHEN EXCLUDED.has_supply_data THEN EXCLUDED.supply_observed_at END, '-infinity'::timestamptz),
				token_structural_signals.observed_at
			),
			updated_at = now()`,
		target, network, largest, top10, hasHolder, mintAuth, freezeAuth, hasAuthority, tokenSupply, hasSupply)
}

// applyStructuralFloor prevents final verdicts from dropping below the
// strongest fresh, verified structural component cached for the token.
func (s *SecurityRadarStore) applyStructuralFloor(ctx context.Context, verdict *SecurityRadarVerdictRecord) {
	if s == nil || s.DB == nil || verdict == nil || verdict.ModuleID != ModuleFinalVerdictEngine {
		return
	}
	target := strings.TrimSpace(verdict.Target)
	if target == "" || IsSecurityRadarInfraTarget(target) {
		return
	}

	cacheCtx, cancel := context.WithTimeout(ctx, structuralCacheTimeout)
	defer cancel()
	var cached tokenStructuralSignals
	err := s.DB.QueryRowContext(cacheCtx, `
		SELECT largest_holder_pct, top10_holder_pct, has_holder_data,
		       mint_authority_present, freeze_authority_present, has_authority_data,
		       holder_observed_at, authority_observed_at,
		       COALESCE(launch_forensics_risk,0), launch_forensics_observed_at
		FROM token_structural_signals
		WHERE target = $1 AND network = $2`, target, normalizeRadarNetwork(verdict.Network)).Scan(
		&cached.LargestHolderPct, &cached.Top10HolderPct, &cached.HasHolderData,
		&cached.MintAuthorityPresent, &cached.FreezeAuthorityPresent, &cached.HasAuthorityData,
		&cached.HolderObservedAt, &cached.AuthorityObservedAt,
		&cached.LaunchForensicsRisk, &cached.LaunchForensicsObservedAt)
	if err != nil {
		return
	}

	floor, observedAt := cached.structuralFloor(time.Now().UTC())
	if floor <= 0 || floor <= verdict.RiskIndex {
		return
	}
	originalRisk := verdict.RiskIndex
	verdict.RiskIndex = floor
	verdict.RiskLevel = riskLevelFromIndex(floor)
	verdict.Grade = gradeFromRiskLevel(verdict.RiskLevel)
	verdict.Recommendation = recommendationFromRiskLevel(verdict.RiskLevel)
	verdict.Signals = nonNilMap(verdict.Signals)
	verdict.Verdict = verdictFromRiskLevel(verdict.ModuleID, verdict.RiskLevel, verdict.Signals)
	if strings.TrimSpace(verdict.Signature) != "" {
		verdict.Signature = signSecurityRadarVerdict(verdict.ModuleID, verdict.Target, verdict.Network, verdict.RiskIndex)
	}

	verdict.Signals["structural_floor_applied"] = true
	verdict.Signals["structural_floor"] = floor
	verdict.Signals["structural_floor_original_risk_index"] = originalRisk
	verdict.Signals["structural_floor_source"] = "cached_verified_onchain_structure"
	verdict.Signals["structural_observed_at"] = observedAt.Format(time.RFC3339)
	if cached.HasHolderData && structuralObservationFresh(time.Now().UTC(), cached.HolderObservedAt) {
		verdict.Signals["structural_largest_holder_pct"] = cached.LargestHolderPct
		verdict.Signals["structural_top10_holder_pct"] = cached.Top10HolderPct
	}
	if cached.HasAuthorityData && structuralObservationFresh(time.Now().UTC(), cached.AuthorityObservedAt) {
		verdict.Signals["structural_mint_authority_present"] = cached.MintAuthorityPresent
		verdict.Signals["structural_freeze_authority_present"] = cached.FreezeAuthorityPresent
	}
	if cached.LaunchForensicsRisk > 0 && structuralObservationFresh(time.Now().UTC(), cached.LaunchForensicsObservedAt) {
		verdict.Signals["structural_launch_forensics_floor"] = cached.LaunchForensicsRisk
	}
	verdict.Evidence = append(nonNilEvidence(verdict.Evidence),
		fmt.Sprintf("Structural floor applied: verified cached on-chain structure observed %s scored %d/100; current event evidence scored %d/100.", observedAt.Format(time.RFC3339), floor, originalRisk))
}

func structuralSignalsVerified(signals map[string]any) bool {
	for _, key := range []string{"verified_evidence", "real_onchain_evidence", "real_offchain_evidence"} {
		if value, ok := structuralSignalBool(signals, key); ok && value {
			return true
		}
	}
	return false
}

func structuralSignalInt(signals map[string]any, key string) (int, bool) {
	value, ok := signals[key]
	if !ok || value == nil {
		return 0, false
	}
	switch typed := value.(type) {
	case int:
		return typed, true
	case int8:
		return int(typed), true
	case int16:
		return int(typed), true
	case int32:
		return int(typed), true
	case int64:
		return int(typed), true
	case uint:
		return int(typed), true
	case uint8:
		return int(typed), true
	case uint16:
		return int(typed), true
	case uint32:
		return int(typed), true
	case uint64:
		return int(typed), true
	case float32:
		return int(typed), true
	case float64:
		return int(typed), true
	case json.Number:
		parsed, err := strconv.ParseFloat(string(typed), 64)
		return int(parsed), err == nil
	case string:
		parsed, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return int(parsed), err == nil
	default:
		return 0, false
	}
}

// CaptureLaunchForensicsFloor stores only deterministic, evidence-backed launch
// timing/funding structure. ORGANIC or missing history never lowers a baseline.
func (s *SecurityRadarStore) CaptureLaunchForensicsFloor(ctx context.Context, target, network string, analysis LaunchForensicsAnalysis) {
	if s == nil || s.DB == nil || !analysis.Available || analysis.StructuralFloor <= 0 {
		return
	}
	target = strings.TrimSpace(target)
	if target == "" || IsSecurityRadarInfraTarget(target) {
		return
	}
	cacheCtx, cancel := context.WithTimeout(ctx, structuralCacheTimeout)
	defer cancel()
	_, _ = s.DB.ExecContext(cacheCtx, `
		INSERT INTO token_structural_signals
			(target,network,launch_forensics_risk,launch_forensics_observed_at,observed_at,updated_at)
		VALUES ($1,$2,$3,now(),now(),now())
		ON CONFLICT (target,network) DO UPDATE SET
			launch_forensics_risk=GREATEST(token_structural_signals.launch_forensics_risk,EXCLUDED.launch_forensics_risk),
			launch_forensics_observed_at=EXCLUDED.launch_forensics_observed_at,
			observed_at=GREATEST(token_structural_signals.observed_at,EXCLUDED.observed_at),
			updated_at=now()`, target, normalizeRadarNetwork(network), analysis.StructuralFloor)
}

func structuralSignalFloat(signals map[string]any, key string) (float64, bool) {
	value, ok := signals[key]
	if !ok || value == nil {
		return 0, false
	}
	var parsed float64
	switch typed := value.(type) {
	case float64:
		parsed = typed
	case float32:
		parsed = float64(typed)
	case int:
		parsed = float64(typed)
	case int64:
		parsed = float64(typed)
	case uint64:
		parsed = float64(typed)
	case json.Number:
		value, err := typed.Float64()
		if err != nil {
			return 0, false
		}
		parsed = value
	case string:
		value, err := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		if err != nil {
			return 0, false
		}
		parsed = value
	default:
		return 0, false
	}
	if math.IsNaN(parsed) || math.IsInf(parsed, 0) {
		return 0, false
	}
	return parsed, true
}

func structuralSignalBool(signals map[string]any, key string) (bool, bool) {
	value, ok := signals[key]
	if !ok || value == nil {
		return false, false
	}
	switch typed := value.(type) {
	case bool:
		return typed, true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(typed))
		return parsed, err == nil
	default:
		return false, false
	}
}

func clampStructuralPercent(value int) int {
	if value < 0 {
		return 0
	}
	if value > 100 {
		return 100
	}
	return value
}

// StructuralBaseline exposes the strongest fresh, verified structural floor
// for quick read paths such as Safe Check. A quick heuristic answer must never
// contradict stronger holder/authority evidence Koschei already verified.
// HARD RULE: holder and authority freshness remain independent; do not replace
// their timestamps with a single aggregate observed_at value.
func (s *SecurityRadarStore) StructuralBaseline(ctx context.Context, target, network string) (int, string, time.Time, bool) {
	if s == nil || s.DB == nil {
		return 0, "", time.Time{}, false
	}
	target = strings.TrimSpace(target)
	if target == "" || IsSecurityRadarInfraTarget(target) {
		return 0, "", time.Time{}, false
	}

	cacheCtx, cancel := context.WithTimeout(ctx, structuralCacheTimeout)
	defer cancel()
	var cached tokenStructuralSignals
	err := s.DB.QueryRowContext(cacheCtx, `
		SELECT largest_holder_pct, top10_holder_pct, has_holder_data,
		       mint_authority_present, freeze_authority_present, has_authority_data,
		       holder_observed_at, authority_observed_at,
		       COALESCE(launch_forensics_risk,0), launch_forensics_observed_at
		FROM token_structural_signals
		WHERE target = $1 AND network = $2`, target, normalizeRadarNetwork(network)).Scan(
		&cached.LargestHolderPct, &cached.Top10HolderPct, &cached.HasHolderData,
		&cached.MintAuthorityPresent, &cached.FreezeAuthorityPresent, &cached.HasAuthorityData,
		&cached.HolderObservedAt, &cached.AuthorityObservedAt,
		&cached.LaunchForensicsRisk, &cached.LaunchForensicsObservedAt)
	if err != nil {
		return 0, "", time.Time{}, false
	}

	floor, observedAt := cached.structuralFloor(time.Now().UTC())
	if floor <= 0 || observedAt.IsZero() {
		return 0, "", time.Time{}, false
	}
	return floor, riskLevelFromIndex(floor), observedAt, true
}
