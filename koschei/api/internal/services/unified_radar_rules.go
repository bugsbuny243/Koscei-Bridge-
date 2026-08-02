package services

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"
)

const UnifiedRadarRulesetVersion = "koschei-unified-radar-rules-v1.0.0"

const (
	UnifiedRuleVolumeLiquidityGap              = "URD-C001"
	UnifiedRuleHolderLiquidityPressure         = "URD-C002"
	UnifiedRuleCreatorSellAcceleration         = "URD-C003"
	UnifiedRuleDominantHolderFirstExit         = "URD-C004"
	UnifiedRuleCrossTokenCreatorHolderTransfer = "URD-C006"
)

const (
	UnifiedVolumeLiquidityGapRatio      = 8.0
	UnifiedHolderLiquidityPressureRatio = 0.50
	UnifiedCreatorSellAccelerationRatio = 2.0
	UnifiedCreatorSellMinimumCount      = 2
	UnifiedCreatorSellMinimumSOL        = 1.0
)

type CreatorSellAcceleration struct {
	Available              bool      `json:"available"`
	Status                 string    `json:"status"`
	Mint                   string    `json:"mint"`
	CreatorWallet          string    `json:"creator_wallet"`
	RecentWindowMinutes    int       `json:"recent_window_minutes"`
	BaselineWindowHours    int       `json:"baseline_window_hours"`
	RecentSellCount        int       `json:"recent_sell_count"`
	RecentSellSOL          float64   `json:"recent_sell_sol"`
	RecentSellTokenAmount  float64   `json:"recent_sell_token_amount"`
	BaselineSellCount      int       `json:"baseline_sell_count"`
	BaselineSellSOL        float64   `json:"baseline_sell_sol"`
	BaselineHourlySellSOL  float64   `json:"baseline_hourly_sell_sol"`
	AccelerationMultiple   float64   `json:"acceleration_multiple"`
	FirstObservedSellBurst bool      `json:"first_observed_sell_burst"`
	Triggered              bool      `json:"triggered"`
	Signatures             []string  `json:"signatures"`
	ObservedAt             time.Time `json:"observed_at"`
	Limitations            []string  `json:"limitations"`
}

type UnifiedRadarSignal struct {
	RuleID         string         `json:"rule_id"`
	Title          string         `json:"title"`
	EvidenceStatus string         `json:"evidence_status"`
	Triggered      bool           `json:"triggered"`
	GradeEffect    string         `json:"grade_effect"`
	Scope          string         `json:"scope"`
	Summary        string         `json:"summary"`
	Metrics        map[string]any `json:"metrics"`
	Thresholds     map[string]any `json:"thresholds"`
	EvidenceKeys   []string       `json:"evidence_keys"`
	Signatures     []string       `json:"signatures"`
	ObservedAt     time.Time      `json:"observed_at"`
	Limitations    []string       `json:"limitations"`
}

type UnifiedRadarBehaviorReport struct {
	RulesetVersion     string                       `json:"ruleset_version"`
	Mint               string                       `json:"mint"`
	CreatorWallet      string                       `json:"creator_wallet,omitempty"`
	Signals            []UnifiedRadarSignal         `json:"signals"`
	Evidence           []ActorDefenseEvidenceRecord `json:"evidence"`
	TriggeredRuleCount int                          `json:"triggered_rule_count"`
	WatchFlagCount     int                          `json:"watch_flag_count"`
	ManualOnly         bool                         `json:"manual_only"`
	GeneratedAt        time.Time                    `json:"generated_at"`
}

type UnifiedRadarVerdict struct {
	Grade           string                `json:"grade"`
	Verdict         string                `json:"verdict"`
	RulesetVersion  string                `json:"ruleset_version"`
	ActorRuleset    string                `json:"actor_ruleset_version"`
	TriggeredRules  []ActorDefenseRuleHit `json:"triggered_rules"`
	WatchFlags      []ActorDefenseRuleHit `json:"watch_flags"`
	DecisionPath    []string              `json:"decision_path"`
	NarrativeSource string                `json:"narrative_source"`
	Signed          bool                  `json:"signed"`
	Signature       string                `json:"signature,omitempty"`
	GeneratedAt     time.Time             `json:"generated_at"`
}

func LoadCreatorSellAcceleration(ctx context.Context, db *sql.DB, mint, creator string, now time.Time) CreatorSellAcceleration {
	mint = strings.TrimSpace(mint)
	creator = strings.TrimSpace(creator)
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	out := CreatorSellAcceleration{
		Status: "trade_history_unavailable", Mint: mint, CreatorWallet: creator,
		RecentWindowMinutes: 60, BaselineWindowHours: 6,
		Signatures: []string{}, Limitations: []string{}, ObservedAt: now,
	}
	if db == nil || mint == "" || creator == "" {
		out.Limitations = append(out.Limitations, "Creator wallet, mint and trade ledger are required.")
		return out
	}
	recentStart := now.Add(-time.Hour)
	baselineStart := recentStart.Add(-6 * time.Hour)
	err := db.QueryRowContext(ctx, `
		SELECT
			count(*) FILTER (WHERE COALESCE(block_time,created_at) >= $3),
			COALESCE(sum(sol_amount) FILTER (WHERE COALESCE(block_time,created_at) >= $3),0)::double precision,
			COALESCE(sum(token_amount) FILTER (WHERE COALESCE(block_time,created_at) >= $3),0)::double precision,
			count(*) FILTER (WHERE COALESCE(block_time,created_at) >= $4 AND COALESCE(block_time,created_at) < $3),
			COALESCE(sum(sol_amount) FILTER (WHERE COALESCE(block_time,created_at) >= $4 AND COALESCE(block_time,created_at) < $3),0)::double precision
		FROM token_trade_events
		WHERE mint=$1 AND trader=$2 AND side='sell'
		  AND COALESCE(block_time,created_at) >= $4`, mint, creator, recentStart, baselineStart).Scan(
		&out.RecentSellCount, &out.RecentSellSOL, &out.RecentSellTokenAmount,
		&out.BaselineSellCount, &out.BaselineSellSOL,
	)
	if err != nil {
		out.Status = "trade_ledger_query_failed"
		out.Limitations = append(out.Limitations, compactUnifiedRadarError(err))
		return out
	}
	rows, err := db.QueryContext(ctx, `
		SELECT signature
		FROM token_trade_events
		WHERE mint=$1 AND trader=$2 AND side='sell'
		  AND COALESCE(block_time,created_at) >= $3
		ORDER BY COALESCE(block_time,created_at) DESC,slot DESC
		LIMIT 10`, mint, creator, recentStart)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var signature string
			if rows.Scan(&signature) == nil && strings.TrimSpace(signature) != "" {
				out.Signatures = append(out.Signatures, strings.TrimSpace(signature))
			}
		}
	}
	out.Available = true
	out.Status = "creator_sell_windows_observed"
	out.BaselineHourlySellSOL = roundUnifiedRadar(out.BaselineSellSOL / 6)
	if out.BaselineHourlySellSOL > 0 {
		out.AccelerationMultiple = roundUnifiedRadar(out.RecentSellSOL / out.BaselineHourlySellSOL)
	} else if out.RecentSellSOL > 0 {
		out.FirstObservedSellBurst = true
	}
	out.Triggered = out.RecentSellCount >= UnifiedCreatorSellMinimumCount &&
		out.RecentSellSOL >= UnifiedCreatorSellMinimumSOL &&
		(out.FirstObservedSellBurst || out.AccelerationMultiple >= UnifiedCreatorSellAccelerationRatio)
	return out
}

func EvaluateUnifiedRadarBehavior(mint, creator string, market TokenMarketSnapshot, holder HolderIntelligence, cluster HolderClusterAnalysis, sales CreatorSellAcceleration, now time.Time) UnifiedRadarBehaviorReport {
	if now.IsZero() {
		now = time.Now().UTC()
	}
	now = now.UTC()
	mint = strings.TrimSpace(mint)
	creator = strings.TrimSpace(creator)
	report := UnifiedRadarBehaviorReport{
		RulesetVersion: UnifiedRadarRulesetVersion, Mint: mint, CreatorWallet: creator,
		Signals: []UnifiedRadarSignal{}, Evidence: []ActorDefenseEvidenceRecord{}, ManualOnly: true, GeneratedAt: now,
	}

	volumeSignal := unifiedVolumeLiquiditySignal(mint, market, now)
	holderSignal := unifiedHolderLiquiditySignal(mint, market, holder, now)
	sellSignal := unifiedCreatorSellSignal(mint, creator, sales, now)
	exitSignal := unifiedDominantHolderExitSignal(mint, cluster, now)
	report.Signals = append(report.Signals, volumeSignal, holderSignal, sellSignal, exitSignal)
	for _, signal := range report.Signals {
		if signal.Triggered {
			report.TriggeredRuleCount++
		}
		if signal.EvidenceStatus == "inferred" {
			report.WatchFlagCount++
		}
		if evidence, ok := unifiedSignalEvidence(creator, mint, signal); ok {
			report.Evidence = append(report.Evidence, evidence)
		}
	}
	return report
}

func EvaluateUnifiedRadarVerdict(target string, actor ActorDefenseRuleVerdict, behavior UnifiedRadarBehaviorReport) UnifiedRadarVerdict {
	triggered := append([]ActorDefenseRuleHit{}, actor.TriggeredRules...)
	watch := append([]ActorDefenseRuleHit{}, actor.WatchFlags...)
	for _, signal := range behavior.Signals {
		hit := unifiedSignalRuleHit(signal)
		if signal.Triggered && (signal.EvidenceStatus == "verified" || signal.EvidenceStatus == "observed") {
			triggered = append(triggered, hit)
		} else if signal.EvidenceStatus == "inferred" {
			watch = append(watch, hit)
		}
	}
	triggered = actorRuleMergeHits(triggered)
	watch = actorRuleMergeHits(watch)
	actorRuleSortHits(triggered)
	actorRuleSortHits(watch)

	grade := "-"
	verdict := "no_grade_trigger"
	decision := []string{
		"The 14 legacy evidence arms, actor investigation and four market/holder behavior rules are joined in one manual Radar dossier.",
		"No weighted score or 0-100 final result is calculated.",
		"INFERRED is watch-only and UNVERIFIED cannot change the grade.",
	}
	if actor.Verdict == "hard_trigger" && actor.Grade != "-" {
		grade = actor.Grade
		verdict = "hard_trigger"
		decision = append(decision, "A VERIFIED actor hard trigger fixed the letter-grade ceiling at "+grade+".")
	} else {
		compoundCount := 0
		for _, hit := range triggered {
			if hit.Tier == "compounding" && (hit.EvidenceStatus == "verified" || hit.EvidenceStatus == "observed") {
				compoundCount++
			}
		}
		for _, hit := range triggered {
			decision = append(decision, fmt.Sprintf("Rule %s [%s/%s]: %s", hit.RuleID, hit.Tier, hit.EvidenceStatus, hit.Summary))
		}
		holderPressure, holderPressureOK := unifiedRadarSignalByRule(behavior, UnifiedRuleHolderLiquidityPressure)
		dominantExit, dominantExitOK := unifiedRadarSignalByRule(behavior, UnifiedRuleDominantHolderFirstExit)
		pressureRatio := unifiedRadarMetricFloat(holderPressure.Metrics["position_liquidity_ratio"])
		severeCompounding := compoundCount >= 2 && holderPressureOK && dominantExitOK && holderPressure.Triggered && dominantExit.Triggered && pressureRatio >= 10
		switch {
		case severeCompounding:
			grade = "C"
			verdict = "severe_compounding_rule"
			decision = append(decision, fmt.Sprintf("Dominant-holder reference position is %.2fx reported liquidity and a transaction-backed dominant-holder exit is present; severity-aware compounding caps the grade at C.", pressureRatio))
		case compoundCount >= 2:
			grade = "B"
			verdict = "compounding_rule"
			decision = append(decision, fmt.Sprintf("%d distinct VERIFIED/OBSERVED compounding rules lowered the baseline by one grade to B; rule IDs and facts are listed above.", compoundCount))
		case compoundCount == 1:
			verdict = "single_observation"
			decision = append(decision, "One compounding rule is visible but cannot issue a letter grade alone.")
		case len(watch) > 0:
			verdict = "watch_only"
			decision = append(decision, "Only watch flags are present; no letter grade is issued.")
		default:
			decision = append(decision, "No grade-changing rule was satisfied; absence of evidence is not an A grade.")
		}
	}
	out := UnifiedRadarVerdict{
		Grade: grade, Verdict: verdict, RulesetVersion: UnifiedRadarRulesetVersion,
		ActorRuleset: ActorDefenseRulesetVersion, TriggeredRules: triggered, WatchFlags: watch,
		DecisionPath: decision, NarrativeSource: "deterministic_rules_only_ai_explains_but_never_grades",
		GeneratedAt: time.Now().UTC(),
	}
	if out.Grade != "-" && len(out.TriggeredRules) > 0 {
		out.Signed = true
		out.Signature = signUnifiedRadarVerdict(strings.TrimSpace(target), out)
	}
	return out
}

func unifiedRadarSignalByRule(report UnifiedRadarBehaviorReport, ruleID string) (UnifiedRadarSignal, bool) {
	for _, signal := range report.Signals {
		if signal.RuleID == ruleID {
			return signal, true
		}
	}
	return UnifiedRadarSignal{}, false
}

func unifiedRadarMetricFloat(value any) float64 {
	switch typed := value.(type) {
	case float64:
		return typed
	case float32:
		return float64(typed)
	case int:
		return float64(typed)
	case int64:
		return float64(typed)
	case json.Number:
		number, _ := typed.Float64()
		return number
	case string:
		number, _ := strconv.ParseFloat(strings.TrimSpace(typed), 64)
		return number
	default:
		return 0
	}
}

func unifiedVolumeLiquiditySignal(mint string, market TokenMarketSnapshot, now time.Time) UnifiedRadarSignal {
	signal := UnifiedRadarSignal{
		RuleID: UnifiedRuleVolumeLiquidityGap, Title: "24h volume / liquidity gap",
		EvidenceStatus: "unverified", GradeEffect: "none", Scope: "market_snapshot",
		Metrics:      map[string]any{"volume_24h_usd": market.Volume24hUSD, "liquidity_usd": market.LiquidityUSD},
		Thresholds:   map[string]any{"minimum_ratio": UnifiedVolumeLiquidityGapRatio},
		EvidenceKeys: []string{}, Signatures: []string{}, Limitations: []string{}, ObservedAt: now,
	}
	if !market.Available || market.LiquidityUSD <= 0 {
		signal.Summary = "Volume/liquidity ratio could not be evaluated because a positive liquidity snapshot is unavailable."
		signal.Limitations = append(signal.Limitations, market.Limitations...)
		return signal
	}
	ratio := roundUnifiedRadar(market.Volume24hUSD / market.LiquidityUSD)
	signal.EvidenceStatus = "observed"
	signal.Metrics["volume_liquidity_ratio"] = ratio
	signal.Triggered = ratio >= UnifiedVolumeLiquidityGapRatio
	if signal.Triggered {
		signal.GradeEffect = "compounding_input"
		signal.Summary = fmt.Sprintf("Observed 24h volume is %.2fx reported liquidity, meeting the explicit %.2fx gap rule.", ratio, UnifiedVolumeLiquidityGapRatio)
	} else {
		signal.Summary = fmt.Sprintf("Observed 24h volume/liquidity ratio is %.2fx and did not meet the %.2fx rule.", ratio, UnifiedVolumeLiquidityGapRatio)
	}
	signal.EvidenceKeys = []string{fmt.Sprintf("market:%s:%s", mint, market.ObservedAt.UTC().Truncate(time.Hour).Format(time.RFC3339))}
	if !market.ObservedAt.IsZero() {
		signal.ObservedAt = market.ObservedAt.UTC()
	}
	return signal
}

func unifiedHolderLiquiditySignal(mint string, market TokenMarketSnapshot, holder HolderIntelligence, now time.Time) UnifiedRadarSignal {
	signal := UnifiedRadarSignal{
		RuleID: UnifiedRuleHolderLiquidityPressure, Title: "Dominant-holder position / liquidity depth",
		EvidenceStatus: "unverified", GradeEffect: "none", Scope: "owner_aggregated_holder_value_vs_reported_liquidity",
		Metrics:      map[string]any{"liquidity_usd": market.LiquidityUSD, "top_holder_percentage": holder.TopOwnerPercentage},
		Thresholds:   map[string]any{"minimum_position_to_liquidity_ratio": UnifiedHolderLiquidityPressureRatio},
		EvidenceKeys: []string{}, Signatures: []string{}, Limitations: []string{}, ObservedAt: now,
	}
	if !holder.Available || market.LiquidityUSD <= 0 {
		signal.Summary = "Holder-position pressure could not be evaluated because owner-aggregated holder value or positive liquidity is unavailable."
		return signal
	}
	topValue := 0.0
	if holder.TopOwnerReferenceUSDValue != nil {
		topValue = *holder.TopOwnerReferenceUSDValue
	} else if holder.TopOwnerBalance > 0 && market.PriceUSD > 0 {
		topValue = holder.TopOwnerBalance * market.PriceUSD
	}
	if topValue <= 0 {
		signal.Summary = "Dominant-holder USD reference value is unavailable; no liquidity-pressure claim is issued."
		return signal
	}
	ratio := roundUnifiedRadar(topValue / market.LiquidityUSD)
	signal.EvidenceStatus = "observed"
	signal.Metrics["top_holder_reference_usd"] = roundUnifiedRadar(topValue)
	signal.Metrics["position_liquidity_ratio"] = ratio
	signal.Triggered = ratio >= UnifiedHolderLiquidityPressureRatio
	if signal.Triggered {
		signal.GradeEffect = "compounding_input"
		signal.Summary = fmt.Sprintf("Dominant-holder reference position equals %.2fx reported liquidity, meeting the explicit %.2fx pressure rule.", ratio, UnifiedHolderLiquidityPressureRatio)
	} else {
		signal.Summary = fmt.Sprintf("Dominant-holder reference position/liquidity ratio is %.2fx and did not meet the %.2fx rule.", ratio, UnifiedHolderLiquidityPressureRatio)
	}
	signal.EvidenceKeys = []string{fmt.Sprintf("holder-liquidity:%s:%s", mint, now.Truncate(time.Hour).Format(time.RFC3339))}
	return signal
}

func unifiedCreatorSellSignal(mint, creator string, sales CreatorSellAcceleration, now time.Time) UnifiedRadarSignal {
	status := "unverified"
	if sales.Available {
		status = "observed"
	}
	if len(sales.Signatures) > 0 {
		status = "verified"
	}
	signal := UnifiedRadarSignal{
		RuleID: UnifiedRuleCreatorSellAcceleration, Title: "Creator sell acceleration",
		EvidenceStatus: status, Triggered: sales.Triggered, GradeEffect: "none", Scope: "creator_trade_ledger_recent_1h_vs_previous_6h_hourly_rate",
		Metrics: map[string]any{
			"recent_sell_count": sales.RecentSellCount, "recent_sell_sol": sales.RecentSellSOL,
			"baseline_sell_count": sales.BaselineSellCount, "baseline_sell_sol": sales.BaselineSellSOL,
			"baseline_hourly_sell_sol": sales.BaselineHourlySellSOL, "acceleration_multiple": sales.AccelerationMultiple,
			"first_observed_sell_burst": sales.FirstObservedSellBurst,
		},
		Thresholds: map[string]any{
			"recent_window_minutes": 60, "baseline_window_hours": 6,
			"minimum_recent_sell_count":     UnifiedCreatorSellMinimumCount,
			"minimum_recent_sell_sol":       UnifiedCreatorSellMinimumSOL,
			"minimum_acceleration_multiple": UnifiedCreatorSellAccelerationRatio,
		},
		EvidenceKeys: []string{}, Signatures: append([]string{}, sales.Signatures...),
		Limitations: append([]string{}, sales.Limitations...), ObservedAt: sales.ObservedAt,
	}
	if signal.ObservedAt.IsZero() {
		signal.ObservedAt = now
	}
	if !sales.Available || creator == "" {
		signal.Summary = "Creator sell acceleration was not evaluated because creator identity or trade-ledger coverage is unavailable."
		return signal
	}
	if signal.Triggered {
		signal.GradeEffect = "compounding_input"
		if sales.FirstObservedSellBurst {
			signal.Summary = fmt.Sprintf("Creator produced %d verified sells totaling %.4f SOL in one hour after no sells were observed in the prior six-hour baseline.", sales.RecentSellCount, sales.RecentSellSOL)
		} else {
			signal.Summary = fmt.Sprintf("Creator one-hour sell flow accelerated to %.2fx the previous six-hour hourly baseline.", sales.AccelerationMultiple)
		}
	} else {
		signal.Summary = "Creator sell history was observed but did not meet the explicit count, SOL and acceleration thresholds together."
	}
	for _, signature := range sales.Signatures {
		signal.EvidenceKeys = append(signal.EvidenceKeys, "creator-sell:"+signature)
	}
	if len(signal.EvidenceKeys) == 0 {
		signal.EvidenceKeys = []string{fmt.Sprintf("creator-sell:%s:%s", mint, now.Truncate(time.Hour).Format(time.RFC3339))}
	}
	return signal
}

func unifiedDominantHolderExitSignal(mint string, cluster HolderClusterAnalysis, now time.Time) UnifiedRadarSignal {
	signal := UnifiedRadarSignal{
		RuleID: UnifiedRuleDominantHolderFirstExit, Title: "Dominant-holder first observed exit",
		EvidenceStatus: "unverified", GradeEffect: "none", Scope: "bounded_holder_transaction_window",
		Metrics: map[string]any{}, Thresholds: map[string]any{"dominant_holder_rank": 1, "minimum_outflow_amount": 0},
		EvidenceKeys: []string{}, Signatures: []string{}, Limitations: []string{}, ObservedAt: now,
	}
	var top *HolderClusterWallet
	for i := range cluster.Wallets {
		wallet := &cluster.Wallets[i]
		if wallet.Rank != 1 {
			continue
		}
		top = wallet
		break
	}
	if top == nil {
		signal.Summary = "Dominant-holder exit was not evaluated because rank-one owner history is unavailable."
		return signal
	}
	observations := append([]HolderClusterFlowObservation{}, top.FlowObservations...)
	sort.SliceStable(observations, func(i, j int) bool {
		if observations[i].Slot == observations[j].Slot {
			return observations[i].Signature < observations[j].Signature
		}
		if observations[i].Slot == 0 {
			return false
		}
		if observations[j].Slot == 0 {
			return true
		}
		return observations[i].Slot < observations[j].Slot
	})
	for _, observation := range observations {
		if observation.Amount <= 0 || strings.TrimSpace(observation.Signature) == "" {
			continue
		}
		signal.Triggered = true
		signal.GradeEffect = "compounding_input"
		signal.EvidenceStatus = "verified"
		signal.Signatures = []string{observation.Signature}
		signal.EvidenceKeys = []string{"dominant-holder-exit:" + observation.Signature}
		signal.Metrics = map[string]any{
			"holder_wallet": top.Wallet, "holder_percentage": top.HolderPercentage,
			"amount": observation.Amount, "destination": observation.Destination,
			"kind": observation.Kind, "slot": observation.Slot,
		}
		complete := top.HistoryExhausted && top.SignaturesObserved > 0 && top.ParsedTransactions >= top.SignaturesObserved
		if complete {
			signal.Scope = "first_exit_in_complete_observed_history"
			signal.Summary = "The first target-token exit in the completely observed dominant-holder history was transaction-backed."
		} else {
			signal.Scope = "earliest_verified_exit_in_bounded_window"
			signal.Summary = "The earliest parsed dominant-holder exit in the bounded investigation window was transaction-backed; it is not claimed as the wallet's all-time first exit."
			signal.Limitations = append(signal.Limitations, "Bounded history cannot prove an all-time first exit unless every observed signature was parsed and history was exhausted.")
		}
		return signal
	}
	signal.EvidenceStatus = "observed"
	signal.Summary = "Rank-one holder history was inspected but no parsed target-token exit was observed in the bounded window."
	return signal
}

func unifiedSignalEvidence(creator, mint string, signal UnifiedRadarSignal) (ActorDefenseEvidenceRecord, bool) {
	creator = strings.TrimSpace(creator)
	mint = strings.TrimSpace(mint)
	if creator == "" || mint == "" || !signal.Triggered || len(signal.EvidenceKeys) == 0 {
		return ActorDefenseEvidenceRecord{}, false
	}
	metadata := map[string]any{
		"unified_rule_id": signal.RuleID, "title": signal.Title, "scope": signal.Scope,
		"threshold_met": signal.Triggered, "metrics": signal.Metrics, "thresholds": signal.Thresholds,
		"summary": signal.Summary, "manual_only": true,
	}
	item := ActorDefenseEvidenceRecord{
		Network: "solana-mainnet", ActorWallet: creator, CounterpartKind: "token", CounterpartID: mint,
		Relation: unifiedSignalRelation(signal.RuleID), VerificationStatus: signal.EvidenceStatus,
		EvidenceKey: signal.EvidenceKeys[0], Source: "unified_manual_radar", ObservedAt: signal.ObservedAt,
		TokenMint: mint, Metadata: metadata,
	}
	if len(signal.Signatures) > 0 {
		item.Signature = signal.Signatures[0]
	}
	if slot, ok := unifiedInt64(signal.Metrics["slot"]); ok {
		item.Slot = slot
	}
	if signal.RuleID == UnifiedRuleCrossTokenCreatorHolderTransfer {
		item.TokenAmount, _ = unifiedFloat64(signal.Metrics["amount"])
		if item.Metadata == nil {
			item.Metadata = map[string]any{}
		}
		item.Metadata["source_wallet"] = unifiedMetricString(signal.Metrics, "source_wallet")
		item.Metadata["destination_wallet"] = unifiedMetricString(signal.Metrics, "destination_wallet")
		item.Metadata["program"] = unifiedMetricString(signal.Metrics, "program")
	}
	return item, true
}

func unifiedSignalRelation(ruleID string) string {
	switch ruleID {
	case UnifiedRuleVolumeLiquidityGap:
		return "market_volume_liquidity_gap"
	case UnifiedRuleHolderLiquidityPressure:
		return "holder_liquidity_depth_pressure"
	case UnifiedRuleCreatorSellAcceleration:
		return "creator_sell_acceleration"
	case UnifiedRuleDominantHolderFirstExit:
		return "dominant_holder_first_exit"
	case UnifiedRuleCrossTokenCreatorHolderTransfer:
		return "cross_token_creator_holder_transfer"
	default:
		return "unified_radar_observation"
	}
}

func unifiedSignalRuleHit(signal UnifiedRadarSignal) ActorDefenseRuleHit {
	return ActorDefenseRuleHit{
		RuleID: signal.RuleID, Title: signal.Title, Tier: "compounding",
		EvidenceStatus: signal.EvidenceStatus, GradeEffect: signal.GradeEffect,
		Count: 1, Summary: signal.Summary, EvidenceKeys: append([]string{}, signal.EvidenceKeys...),
		Signatures: append([]string{}, signal.Signatures...), Facts: map[string]any{
			"scope": signal.Scope, "metrics": signal.Metrics, "thresholds": signal.Thresholds,
		},
	}
}

func signUnifiedRadarVerdict(target string, verdict UnifiedRadarVerdict) string {
	ruleIDs := []string{}
	evidenceKeys := []string{}
	signatures := []string{}
	for _, hit := range verdict.TriggeredRules {
		ruleIDs = append(ruleIDs, hit.RuleID)
		evidenceKeys = append(evidenceKeys, hit.EvidenceKeys...)
		signatures = append(signatures, hit.Signatures...)
	}
	sort.Strings(ruleIDs)
	sort.Strings(evidenceKeys)
	sort.Strings(signatures)
	payload := map[string]any{
		"target": target, "ruleset_version": verdict.RulesetVersion,
		"actor_ruleset_version": verdict.ActorRuleset, "grade": verdict.Grade,
		"rule_ids": ruleIDs, "evidence_keys": evidenceKeys, "signatures": signatures,
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return "koschei-unified:" + hex.EncodeToString(sum[:])
}

func unifiedInt64(value any) (int64, bool) {
	switch typed := value.(type) {
	case int64:
		return typed, true
	case int:
		return int64(typed), true
	case float64:
		return int64(typed), true
	default:
		return 0, false
	}
}

func unifiedFloat64(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, true
	case float32:
		return float64(typed), true
	case int:
		return float64(typed), true
	case int64:
		return float64(typed), true
	default:
		return 0, false
	}
}

func roundUnifiedRadar(value float64) float64 {
	if value == 0 {
		return 0
	}
	return float64(int64(value*10000+0.5)) / 10000
}

func compactUnifiedRadarError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.Join(strings.Fields(strings.TrimSpace(err.Error())), " ")
	if len(message) > 180 {
		message = message[:180]
	}
	return message
}
