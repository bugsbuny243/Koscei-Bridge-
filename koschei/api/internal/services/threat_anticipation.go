package services

import (
	"fmt"
	"strings"
	"time"
)

const ThreatAnticipationVersion = "koschei-threat-anticipation-v1.0.0"

type ThreatAnticipationInput struct {
	Target   string
	Market   TokenMarketSnapshot
	Holder   HolderIntelligence
	Cluster  HolderClusterAnalysis
	Arms     []SecurityRadarVerdict
	Behavior UnifiedRadarBehaviorReport
}

type ThreatExitCapacity struct {
	Available                 bool     `json:"available"`
	Status                    string   `json:"status"`
	DominantOwnerWallet       string   `json:"dominant_owner_wallet,omitempty"`
	OwnerResolved             bool     `json:"owner_resolved"`
	OwnerPercentage           float64  `json:"owner_percentage"`
	OwnerBalance              float64  `json:"owner_balance"`
	OwnerReferenceUSDValue    *float64 `json:"owner_reference_usd_value,omitempty"`
	LiquidityUSD              float64  `json:"liquidity_usd"`
	PositionLiquidityMultiple *float64 `json:"position_liquidity_multiple,omitempty"`
	Capacity                  string   `json:"capacity"`
	Interpretation            string   `json:"interpretation"`
	Limitations               []string `json:"limitations"`
}

type ThreatPathway struct {
	ID               string   `json:"id"`
	Label            string   `json:"label"`
	Status           string   `json:"status"`
	Capacity         string   `json:"capacity"`
	EvidenceStatus   string   `json:"evidence_status"`
	Summary          string   `json:"summary"`
	EvidenceKeys     []string `json:"evidence_keys"`
	RequiredEvidence []string `json:"required_evidence,omitempty"`
	Limitations      []string `json:"limitations,omitempty"`
}

type ThreatScenario struct {
	ID             string   `json:"id"`
	Title          string   `json:"title"`
	Classification string   `json:"classification"`
	EvidenceStatus string   `json:"evidence_status"`
	Basis          string   `json:"basis"`
	EvidenceKeys   []string `json:"evidence_keys"`
	NextSignals    []string `json:"next_signals"`
}

type ThreatWatchSignal struct {
	ID             string `json:"id"`
	Status         string `json:"status"`
	Severity       string `json:"severity"`
	Title          string `json:"title"`
	Trigger        string `json:"trigger"`
	EvidenceSource string `json:"evidence_source"`
}

type RugPathwayAssessment struct {
	ProbabilityMode string   `json:"probability_mode"`
	Conclusion      string   `json:"conclusion"`
	OpenPaths       []string `json:"open_paths"`
	ObservedPaths   []string `json:"observed_paths"`
	ClosedPaths     []string `json:"closed_paths"`
	WatchPaths      []string `json:"watch_paths"`
	UnknownPaths    []string `json:"unknown_paths"`
}

type ThreatAnticipationReport struct {
	Version         string               `json:"version"`
	Target          string               `json:"target"`
	Status          string               `json:"status"`
	PrimaryExposure string               `json:"primary_exposure"`
	ExitCapacity    ThreatExitCapacity   `json:"exit_capacity"`
	RugAssessment   RugPathwayAssessment `json:"rug_pathway_assessment"`
	Pathways        []ThreatPathway      `json:"pathways"`
	Scenarios       []ThreatScenario     `json:"scenarios"`
	WatchSignals    []ThreatWatchSignal  `json:"watch_signals"`
	MissingEvidence []string             `json:"missing_evidence"`
	GeneratedAt     time.Time            `json:"generated_at"`
	EvidencePolicy  map[string]bool      `json:"evidence_policy"`
}

func BuildThreatAnticipation(in ThreatAnticipationInput) ThreatAnticipationReport {
	out := ThreatAnticipationReport{
		Version:         ThreatAnticipationVersion,
		Target:          strings.TrimSpace(in.Target),
		Status:          "insufficient_evidence",
		PrimaryExposure: "No evidence-backed threat pathway could be prioritized.",
		Pathways:        []ThreatPathway{}, Scenarios: []ThreatScenario{}, WatchSignals: []ThreatWatchSignal{}, MissingEvidence: []string{},
		GeneratedAt: time.Now().UTC(),
		EvidencePolicy: map[string]bool{
			"predicts_intent":                             false,
			"numeric_rug_probability_disabled":            true,
			"capacity_is_not_intent":                      true,
			"unverified_paths_cannot_change_grade":        true,
			"deterministic_verdict_remains_authoritative": true,
		},
	}

	out.ExitCapacity = buildThreatExitCapacity(in.Holder, in.Market)
	out.Pathways = append(out.Pathways,
		buildDominantHolderPath(out.ExitCapacity),
		buildAuthorityThreatPath(in.Arms, true),
		buildAuthorityThreatPath(in.Arms, false),
		buildLiquidityThreatPath(in.Arms),
		buildCoordinatedExitPath(in.Cluster),
		buildCreatorSellPath(in.Behavior),
	)
	out.RugAssessment = summarizeRugPathways(out.Pathways)
	out.PrimaryExposure = primaryThreatExposure(out.Pathways, out.ExitCapacity)
	out.Scenarios = buildThreatScenarios(in, out)
	out.WatchSignals = buildThreatWatchSignals(in, out)
	out.MissingEvidence = threatMissingEvidence(in, out)
	if out.ExitCapacity.Available || threatHasUsablePath(out.Pathways) {
		out.Status = "evidence_backed_pathway_analysis"
	}
	return out
}

func buildThreatExitCapacity(holder HolderIntelligence, market TokenMarketSnapshot) ThreatExitCapacity {
	out := ThreatExitCapacity{Status: "holder_capacity_unavailable", Capacity: "unknown", Limitations: []string{}}
	var row *HolderIntelligenceRow
	for i := range holder.Rows {
		candidate := &holder.Rows[i]
		if candidate.ExcludedFromHolderRisk || !candidate.RiskBearing {
			continue
		}
		row = candidate
		break
	}
	if row == nil && holder.TopOwnerPercentage <= 0 {
		out.Limitations = append(out.Limitations, "A risk-bearing owner-resolved holder position is required.")
		return out
	}
	out.Available = true
	out.Status = "observed_owner_capacity"
	out.OwnerPercentage = holder.TopOwnerPercentage
	out.OwnerBalance = holder.TopOwnerBalance
	out.OwnerReferenceUSDValue = holder.TopOwnerReferenceUSDValue
	if row != nil {
		out.DominantOwnerWallet = strings.TrimSpace(row.OwnerWallet)
		out.OwnerResolved = row.OwnerResolved
		out.OwnerPercentage = firstPositiveFloat(row.CirculatingPercentage, row.RawPercentage, holder.TopOwnerPercentage)
		out.OwnerBalance = row.Balance
		out.OwnerReferenceUSDValue = row.ReferenceUSDValue
	}
	out.LiquidityUSD = market.LiquidityUSD
	if out.OwnerReferenceUSDValue != nil && market.LiquidityUSD > 0 {
		multiple := threatRound(*out.OwnerReferenceUSDValue / market.LiquidityUSD)
		out.PositionLiquidityMultiple = &multiple
	}
	out.Capacity = threatCapacity(out.OwnerPercentage, out.PositionLiquidityMultiple)
	out.Interpretation = fmt.Sprintf("A risk-bearing owner controls %.4f%% of supply. This proves market-impact capacity, not intent to sell.", out.OwnerPercentage)
	if out.PositionLiquidityMultiple != nil {
		out.Interpretation += fmt.Sprintf(" The reference position value is %.2fx observed market liquidity; this is not guaranteed liquidation value.", *out.PositionLiquidityMultiple)
	} else {
		out.Limitations = append(out.Limitations, "Observed liquidity or a reference owner position value is unavailable, so exit leverage could not be calculated.")
	}
	if !out.OwnerResolved {
		out.Limitations = append(out.Limitations, "The dominant control surface is not owner-resolved; wallet attribution remains incomplete.")
	}
	return out
}

func buildDominantHolderPath(exit ThreatExitCapacity) ThreatPathway {
	path := ThreatPathway{
		ID: "dominant_holder_exit", Label: "Dominant-holder market exit", Status: "unknown", Capacity: exit.Capacity,
		EvidenceStatus: "unverified", Summary: "Dominant-holder exit capacity could not be evaluated.",
		EvidenceKeys: []string{"holder_intelligence.top_owner_percentage", "market.liquidity_usd"},
	}
	if !exit.Available {
		path.RequiredEvidence = []string{"owner-resolved risk-bearing holder concentration", "market liquidity snapshot"}
		return path
	}
	path.EvidenceStatus = "observed"
	switch exit.Capacity {
	case "critical", "high", "elevated":
		path.Status = "open"
		path.Summary = fmt.Sprintf("A single risk-bearing owner controls %.4f%% of supply and has %s market-impact capacity. This is an open exit pathway, not proof that an exit is planned.", exit.OwnerPercentage, exit.Capacity)
	default:
		path.Status = "limited"
		path.Summary = fmt.Sprintf("A risk-bearing owner controls %.4f%% of supply; material exit capacity is currently limited by the observed position size.", exit.OwnerPercentage)
	}
	return path
}

func buildAuthorityThreatPath(arms []SecurityRadarVerdict, mint bool) ThreatPathway {
	id, label, key := "freeze_abuse", "Freeze/account restriction abuse", "freeze_authority_present"
	if mint {
		id, label, key = "mint_inflation", "Mint inflation", "mint_authority_present"
	}
	path := ThreatPathway{ID: id, Label: label, Status: "unknown", Capacity: "unknown", EvidenceStatus: "unverified", EvidenceKeys: []string{"token_authority_scanner." + key}}
	arm, ok := threatArm(arms, ModuleTokenAuthorityScanner)
	if !ok {
		path.Summary = label + " pathway is unknown because token authority evidence is unavailable."
		path.RequiredEvidence = []string{"parsed mint account authority state"}
		return path
	}
	value, known := threatBool(arm.Signals[key])
	if !known {
		path.Summary = label + " pathway is unknown because the authority field was not parsed."
		path.RequiredEvidence = []string{"parsed mint account authority state"}
		return path
	}
	path.EvidenceStatus = threatArmEvidenceStatus(arm)
	if value {
		path.Status = "open"
		path.Capacity = "high"
		path.Summary = label + " pathway remains technically available because the authority is present."
	} else {
		path.Status = "closed"
		path.Capacity = "none_observed"
		path.Summary = label + " pathway is closed under the currently observed authority state."
	}
	return path
}

func buildLiquidityThreatPath(arms []SecurityRadarVerdict) ThreatPathway {
	path := ThreatPathway{
		ID: "liquidity_removal", Label: "Liquidity removal", Status: "unknown", Capacity: "unknown", EvidenceStatus: "unverified",
		Summary:          "Liquidity amount is not the same as liquidity control. LP ownership, burn/lock state and unlock conditions are not yet verified.",
		EvidenceKeys:     []string{"liquidity_movement", "raydium_pool_guardian"},
		RequiredEvidence: []string{"LP mint and LP token owner", "burn or locker proof", "unlock timestamp", "parsed add/remove signatures", "pool reserve deltas"},
	}
	liquidity, hasLiquidity := threatArm(arms, ModuleLiquidityMovement)
	raydium, hasRaydium := threatArm(arms, ModuleRaydiumPoolGuardian)
	for _, arm := range []SecurityRadarVerdict{liquidity, raydium} {
		if arm.ModuleID == "" {
			continue
		}
		if removed, ok := threatBool(firstThreatSignal(arm.Signals, "liquidity_removal_verified", "liquidity_removed")); ok && removed {
			path.Status = "observed"
			path.Capacity = "critical"
			path.EvidenceStatus = threatArmEvidenceStatus(arm)
			path.Summary = "A liquidity removal event is present in the attached parsed evidence. Actor attribution must still be read from the evidence row."
			return path
		}
		if burned, ok := threatBool(firstThreatSignal(arm.Signals, "lp_tokens_burned", "lp_burned")); ok && burned {
			path.Status = "closed"
			path.Capacity = "none_observed"
			path.EvidenceStatus = threatArmEvidenceStatus(arm)
			path.Summary = "LP burn evidence indicates that the observed liquidity position cannot be withdrawn through ordinary LP redemption."
			return path
		}
		status := strings.ToLower(strings.TrimSpace(threatString(firstThreatSignal(arm.Signals, "lp_lock_status", "liquidity_lock_status"))))
		switch status {
		case "locked", "burned":
			path.Status = "closed"
			path.Capacity = "none_observed"
			path.EvidenceStatus = threatArmEvidenceStatus(arm)
			path.Summary = "Liquidity control is reported as " + status + " by the attached evidence. Unlock conditions must remain visible."
			return path
		case "unlocked", "partially_locked", "partial":
			path.Status = "open"
			path.Capacity = "high"
			path.EvidenceStatus = threatArmEvidenceStatus(arm)
			path.Summary = "Liquidity control is reported as " + status + "; an LP-holder withdrawal pathway remains available."
			return path
		}
	}
	if hasLiquidity || hasRaydium {
		path.EvidenceStatus = "observed"
		path.Limitations = append(path.Limitations, "Pool or market-liquidity evidence exists, but control/lock evidence is incomplete.")
	}
	return path
}

func buildCoordinatedExitPath(cluster HolderClusterAnalysis) ThreatPathway {
	path := ThreatPathway{
		ID: "coordinated_holder_exit", Label: "Coordinated holder exit", Status: "unknown", Capacity: "unknown", EvidenceStatus: "unverified",
		Summary: "Coordinated exit evidence is unavailable.", EvidenceKeys: []string{"holder_cluster.flow", "holder_cluster.shared_funding_groups"},
	}
	if !cluster.Available {
		path.RequiredEvidence = []string{"parsed holder-wallet histories for at least three risk-bearing owners"}
		path.Limitations = append(path.Limitations, cluster.Limitations...)
		return path
	}
	path.EvidenceStatus = "observed"
	if cluster.Flow.CommonExitGroupCount > 0 {
		path.Status = "observed"
		path.Capacity = "high"
		path.Summary = fmt.Sprintf("%d repeated common-exit group(s) were observed across bounded holder histories.", cluster.Flow.CommonExitGroupCount)
		return path
	}
	if cluster.SharedFundingGroupCount > 0 || cluster.SynchronizedWalletCount >= 2 || cluster.LinkedHolderPercentage >= 20 {
		path.Status = "watch"
		path.Capacity = "elevated"
		path.Summary = "Funding, timing or linked-holder evidence supports a coordinated-exit watch scenario, but no common exit is confirmed."
		return path
	}
	path.Status = "not_observed"
	path.Capacity = "unknown"
	path.Summary = "No coordinated exit relation was observed inside the bounded holder evidence window. Absence inside a bounded window is not proof that coordination is impossible."
	return path
}

func buildCreatorSellPath(behavior UnifiedRadarBehaviorReport) ThreatPathway {
	path := ThreatPathway{
		ID: "creator_sell_acceleration", Label: "Creator sell acceleration", Status: "unknown", Capacity: "unknown", EvidenceStatus: "unverified",
		Summary: "Creator sell-window evidence was not attached.", EvidenceKeys: []string{"behavior_signals.URD-C003"},
		RequiredEvidence: []string{"creator-resolved trade ledger with parsed sell signatures"},
	}
	for _, signal := range behavior.Signals {
		if signal.RuleID != UnifiedRuleCreatorSellAcceleration {
			continue
		}
		path.EvidenceStatus = signal.EvidenceStatus
		path.RequiredEvidence = nil
		path.Summary = signal.Summary
		if signal.Triggered {
			path.Status = "observed"
			path.Capacity = "high"
		} else if signal.EvidenceStatus == "verified" || signal.EvidenceStatus == "observed" {
			path.Status = "not_observed"
			path.Capacity = "unknown"
		}
		return path
	}
	return path
}

func summarizeRugPathways(paths []ThreatPathway) RugPathwayAssessment {
	out := RugPathwayAssessment{ProbabilityMode: "not_scored", OpenPaths: []string{}, ObservedPaths: []string{}, ClosedPaths: []string{}, WatchPaths: []string{}, UnknownPaths: []string{}}
	for _, path := range paths {
		switch path.Status {
		case "open":
			out.OpenPaths = append(out.OpenPaths, path.Label)
		case "observed":
			out.ObservedPaths = append(out.ObservedPaths, path.Label)
		case "closed":
			out.ClosedPaths = append(out.ClosedPaths, path.Label)
		case "watch":
			out.WatchPaths = append(out.WatchPaths, path.Label)
		case "unknown":
			out.UnknownPaths = append(out.UnknownPaths, path.Label)
		}
	}
	parts := []string{}
	if len(out.ObservedPaths) > 0 {
		parts = append(parts, "Observed pathway: "+strings.Join(out.ObservedPaths, ", ")+".")
	}
	if len(out.OpenPaths) > 0 {
		parts = append(parts, "Open pathway: "+strings.Join(out.OpenPaths, ", ")+".")
	}
	if len(out.ClosedPaths) > 0 {
		parts = append(parts, "Closed under current evidence: "+strings.Join(out.ClosedPaths, ", ")+".")
	}
	if len(out.UnknownPaths) > 0 {
		parts = append(parts, "Unknown pending evidence: "+strings.Join(out.UnknownPaths, ", ")+".")
	}
	if len(parts) == 0 {
		parts = append(parts, "No rug pathway could be classified from the attached evidence.")
	}
	out.Conclusion = strings.Join(parts, " ") + " Koschei does not assign a numeric rug probability or infer intent."
	return out
}

func primaryThreatExposure(paths []ThreatPathway, exit ThreatExitCapacity) string {
	for _, path := range paths {
		if path.ID == "liquidity_removal" && path.Status == "observed" {
			return "Verified/observed liquidity-removal evidence is the primary exposure."
		}
	}
	for _, path := range paths {
		if path.ID == "dominant_holder_exit" && path.Status == "open" {
			return fmt.Sprintf("Dominant-holder exit capacity is the primary exposure: %.4f%% of supply, capacity %s.", exit.OwnerPercentage, exit.Capacity)
		}
	}
	for _, path := range paths {
		if path.Status == "open" || path.Status == "observed" || path.Status == "watch" {
			return path.Summary
		}
	}
	return "No evidence-backed threat pathway could be prioritized."
}

func buildThreatScenarios(in ThreatAnticipationInput, report ThreatAnticipationReport) []ThreatScenario {
	out := []ThreatScenario{}
	if report.ExitCapacity.Available && (report.ExitCapacity.Capacity == "critical" || report.ExitCapacity.Capacity == "high" || report.ExitCapacity.Capacity == "elevated") {
		out = append(out, ThreatScenario{
			ID: "direct_market_exit", Title: "Direct or staged market exit", Classification: "capacity_scenario", EvidenceStatus: "observed",
			Basis:        report.ExitCapacity.Interpretation,
			EvidenceKeys: []string{"holder_intelligence.rows[0]", "market.liquidity_usd"},
			NextSignals:  []string{"dominant owner balance decreases", "first parsed DEX/aggregator sell", "transfer to a known exchange or service deposit", "sell frequency or sold amount accelerates"},
		})
	}
	if report.ExitCapacity.OwnerPercentage >= 20 {
		out = append(out, ThreatScenario{
			ID: "wallet_fragmentation", Title: "Wallet fragmentation before exit", Classification: "watch_scenario", EvidenceStatus: "inferred",
			Basis:        "A large owner has enough inventory to split the position across multiple wallets; no fragmentation is claimed until transfers are observed.",
			EvidenceKeys: []string{"holder_intelligence.top_owner_percentage"},
			NextSignals:  []string{"transfers to multiple newly funded wallets", "similar transfer amounts inside a short window", "recipient wallets interact with the same DEX route"},
		})
	}
	for _, path := range report.Pathways {
		switch path.ID {
		case "coordinated_holder_exit":
			if path.Status == "observed" || path.Status == "watch" {
				out = append(out, ThreatScenario{ID: "coordinated_exit", Title: "Coordinated linked-holder exit", Classification: "watch_scenario", EvidenceStatus: path.EvidenceStatus, Basis: path.Summary, EvidenceKeys: path.EvidenceKeys, NextSignals: []string{"linked holders sell inside the same observation window", "multiple holders route tokens to a common recipient", "shared-funder wallets reduce balances together"}})
			}
		case "liquidity_removal":
			if path.Status == "unknown" || path.Status == "open" || path.Status == "observed" {
				out = append(out, ThreatScenario{ID: "liquidity_control_event", Title: "Liquidity control change", Classification: "evidence_request", EvidenceStatus: path.EvidenceStatus, Basis: path.Summary, EvidenceKeys: path.EvidenceKeys, NextSignals: []string{"LP token transfer", "locker unlock approaches or executes", "parsed remove-liquidity instruction", "pool reserves fall without matching market flow"}})
			}
		}
	}
	for _, row := range in.Holder.Rows {
		if row.RepeatDominantHolder {
			out = append(out, ThreatScenario{ID: "repeat_actor_redeployment", Title: "Repeat dominant actor reuse", Classification: "observed_actor_scenario", EvidenceStatus: "observed", Basis: "The same owner-resolved wallet has appeared as a dominant holder across multiple scanned tokens.", EvidenceKeys: []string{"holder_intelligence.rows.repeat_dominant_matches"}, NextSignals: []string{"same wallet appears in another launch", "creator or funding relation repeats", "similar exit route appears across tokens"}})
			break
		}
	}
	return out
}

func buildThreatWatchSignals(in ThreatAnticipationInput, report ThreatAnticipationReport) []ThreatWatchSignal {
	out := []ThreatWatchSignal{}
	if report.ExitCapacity.Available {
		status := "recommended_monitor"
		if report.ExitCapacity.OwnerResolved {
			status = "ready_for_snapshot_monitor"
		}
		out = append(out, ThreatWatchSignal{ID: "dominant_owner_balance_drop", Status: status, Severity: threatWatchSeverity(report.ExitCapacity.Capacity), Title: "Dominant owner balance reduction", Trigger: "Alert on any owner-resolved balance decrease; elevate when cumulative movement reaches 1% of total supply.", EvidenceSource: "owner-resolved holder snapshots"})
		out = append(out, ThreatWatchSignal{ID: "dominant_owner_fragmentation", Status: status, Severity: "high", Title: "Dominant owner wallet fragmentation", Trigger: "Alert when the dominant owner transfers token inventory to multiple previously unseen wallets inside one observation window.", EvidenceSource: "parsed token transfers and actor index"})
	}
	for _, path := range report.Pathways {
		if path.ID == "liquidity_removal" && path.Status != "closed" {
			out = append(out, ThreatWatchSignal{ID: "lp_control_change", Status: "requires_lp_evidence", Severity: "critical", Title: "LP ownership, unlock or reserve change", Trigger: "Alert on LP-token movement, locker unlock, remove-liquidity instructions or unexplained reserve decline.", EvidenceSource: "LP mint, locker and pool reserve evidence"})
		}
		if path.ID == "coordinated_holder_exit" && (path.Status == "observed" || path.Status == "watch") {
			out = append(out, ThreatWatchSignal{ID: "linked_holder_same_window_exit", Status: "recommended_monitor", Severity: "high", Title: "Linked holders exit in the same window", Trigger: "Alert when two or more linked holders reduce balances or route tokens to a common recipient in the same observation window.", EvidenceSource: "holder cluster flow intelligence"})
		}
	}
	if len(in.Behavior.Signals) == 0 {
		out = append(out, ThreatWatchSignal{ID: "creator_sell_acceleration", Status: "requires_trade_ledger", Severity: "high", Title: "Creator sell acceleration", Trigger: "Compare the latest one-hour creator sell window with the bounded six-hour baseline.", EvidenceSource: "creator-resolved parsed trade ledger"})
	}
	return out
}

func threatMissingEvidence(in ThreatAnticipationInput, report ThreatAnticipationReport) []string {
	out := []string{}
	for _, path := range report.Pathways {
		if path.Status == "unknown" {
			out = appendUniqueThreat(out, path.RequiredEvidence...)
		}
	}
	if report.ExitCapacity.PositionLiquidityMultiple == nil {
		out = appendUniqueThreat(out, "owner reference position value and observed liquidity for exit leverage")
	}
	out = appendUniqueThreat(out, "token and quote reserve balances for deterministic sell-impact simulation")
	if !in.Cluster.Available {
		out = appendUniqueThreat(out, "bounded parsed histories for at least three risk-bearing holder owners")
	}
	return out
}

func threatArm(arms []SecurityRadarVerdict, moduleID string) (SecurityRadarVerdict, bool) {
	for _, arm := range arms {
		if strings.TrimSpace(arm.ModuleID) == moduleID {
			return arm, true
		}
	}
	return SecurityRadarVerdict{}, false
}

func threatArmEvidenceStatus(arm SecurityRadarVerdict) string {
	if arm.Signals != nil {
		if status := strings.ToLower(strings.TrimSpace(threatString(arm.Signals["evidence_status"]))); status != "" {
			return status
		}
	}
	if arm.Signed {
		return "verified"
	}
	return "observed"
}

func threatBool(value any) (bool, bool) {
	switch v := value.(type) {
	case bool:
		return v, true
	case string:
		switch strings.ToLower(strings.TrimSpace(v)) {
		case "true", "1", "yes", "on", "present", "open":
			return true, true
		case "false", "0", "no", "off", "revoked", "closed":
			return false, true
		}
	}
	return false, false
}

func threatString(value any) string {
	if value == nil {
		return ""
	}
	return strings.TrimSpace(fmt.Sprint(value))
}

func firstThreatSignal(signals map[string]any, keys ...string) any {
	for _, key := range keys {
		if signals == nil {
			return nil
		}
		if value, ok := signals[key]; ok {
			return value
		}
	}
	return nil
}

func firstPositiveFloat(values ...float64) float64 {
	for _, value := range values {
		if value > 0 {
			return value
		}
	}
	return 0
}

func threatCapacity(ownerPercentage float64, multiple *float64) string {
	if ownerPercentage >= 50 || (multiple != nil && *multiple >= 5) {
		return "critical"
	}
	if ownerPercentage >= 20 || (multiple != nil && *multiple >= 1) {
		return "high"
	}
	if ownerPercentage >= 10 || (multiple != nil && *multiple >= 0.5) {
		return "elevated"
	}
	return "limited"
}

func threatWatchSeverity(capacity string) string {
	switch capacity {
	case "critical":
		return "critical"
	case "high", "elevated":
		return "high"
	default:
		return "watch"
	}
}

func threatHasUsablePath(paths []ThreatPathway) bool {
	for _, path := range paths {
		if path.Status != "unknown" {
			return true
		}
	}
	return false
}

func appendUniqueThreat(dst []string, values ...string) []string {
	seen := map[string]bool{}
	for _, value := range dst {
		seen[strings.TrimSpace(value)] = true
	}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		dst = append(dst, value)
	}
	return dst
}

func threatRound(value float64) float64 {
	if value <= 0 {
		return 0
	}
	return float64(int64(value*100+0.5)) / 100
}
