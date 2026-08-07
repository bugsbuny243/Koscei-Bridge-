package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"os"
	"strings"
	"time"
)

const (
	SecurityRadarRuleVersion = "koschei-security-radar-v2-live-evidence"
	SecurityRadarProvider    = "alchemy"
	SecurityRadarWatchMode   = "polling"

	ModulePumpSybilRadar        = "pump_sybil_radar"
	ModuleRaydiumPoolGuardian   = "raydium_pool_guardian"
	ModuleWalletlessClaimShield = "walletless_claim_shield"
)

type SecurityRadarRequest struct {
	Target  string `json:"target"`
	Network string `json:"network"`
	Mode    string `json:"mode"`
}

type SecurityRadarVerdict struct {
	Module         string         `json:"module"`
	ModuleID       string         `json:"module_id"`
	Target         string         `json:"target"`
	Network        string         `json:"network"`
	Grade          string         `json:"grade"`
	RiskIndex      int            `json:"risk_index"`
	RiskLevel      string         `json:"risk_level"`
	Verdict        string         `json:"verdict"`
	Recommendation string         `json:"recommendation"`
	Signals        map[string]any `json:"signals"`
	Evidence       []string       `json:"evidence"`
	GeneratedAt    string         `json:"generated_at"`
	RuleVersion    string         `json:"rule_version"`
	Signed         bool           `json:"signed"`
	Signature      string         `json:"signature"`
}

type SecurityRadarBundle struct {
	Target                 string               `json:"target"`
	Network                string               `json:"network"`
	Provider               string               `json:"provider"`
	WatchMode              string               `json:"watch_mode"`
	PumpSybilRadar         SecurityRadarVerdict `json:"pump_sybil_radar"`
	RaydiumPoolGuardian    SecurityRadarVerdict `json:"raydium_pool_guardian"`
	WalletlessClaimShield  SecurityRadarVerdict `json:"walletless_claim_shield"`
	CustomerSummary        string               `json:"customer_summary"`
	CustomerRecommendation string               `json:"customer_recommendation"`
	Metadata               map[string]any       `json:"metadata"`
}

type SecurityRadarFinalVerdict struct {
	Grade          string `json:"grade"`
	RiskIndex      int    `json:"risk_index"`
	RiskLevel      string `json:"risk_level"`
	Verdict        string `json:"verdict,omitempty"`
	Recommendation string `json:"recommendation"`
	RuleVersion    string `json:"rule_version"`
	Signed         bool   `json:"signed"`
	Signature      string `json:"signature,omitempty"`
}

type radarEvidenceProfile struct {
	Target                          string
	Network                         string
	RPCConfigured                   bool
	LiveRPC                         bool
	DataQuality                     string
	EvidenceStatus                  string
	AccountExists                   bool
	AccountOwner                    string
	AccountExecutable               bool
	IsTokenMint                     bool
	MintAuthorityPresent            bool
	FreezeAuthorityPresent          bool
	TokenSupply                     float64
	LargestHolderPct                int
	Top10HolderPct                  int
	RawLargestHolderPct             int
	RawTop10HolderPct               int
	LargestAccounts                 int
	HolderRoles                     HolderRoleAnalysis
	HolderCluster                   HolderClusterAnalysis
	FundingRecurrence               FundingRecurrenceAnalysis
	TargetOldestBlockTime           int64
	TargetOldestSlot                int64
	RecentSignatureCount            int
	FailedSignatureCount            int
	SignatureWindowSeconds          int64
	TargetSignatureHistoryExhausted bool
	TargetSignatureTimingObserved   bool
	LatestSignature                 string
	LatestSlot                      int64
	Errors                          []string
}

func AnalyzeSecurityRadars(req SecurityRadarRequest) SecurityRadarBundle {
	req.Target = strings.TrimSpace(req.Target)
	req.Network = strings.TrimSpace(req.Network)
	req.Mode = strings.TrimSpace(req.Mode)
	if req.Network == "" {
		req.Network = "solana-mainnet"
	}
	if req.Mode == "" {
		req.Mode = SecurityRadarWatchMode
	}

	generatedAt := time.Now().UTC().Format(time.RFC3339)
	profile := collectRadarEvidence(req)
	pump := buildPumpSybilVerdict(req, profile, generatedAt)
	raydium := buildRaydiumPoolVerdict(req, profile, generatedAt)
	shield := buildClaimShieldVerdict(req, profile, generatedAt)
	final := FinalSecurityRadarVerdict(SecurityRadarBundle{
		PumpSybilRadar:      pump,
		RaydiumPoolGuardian: raydium,
	})

	summary := "Koschei Security Radar used live Solana RPC evidence where available."
	if !profile.LiveRPC {
		summary = "Koschei Security Radar could not collect enough live Solana evidence for a full intelligence verdict."
	}

	return SecurityRadarBundle{
		Target:                 req.Target,
		Network:                req.Network,
		Provider:               SecurityRadarProvider,
		WatchMode:              SecurityRadarWatchMode,
		PumpSybilRadar:         pump,
		RaydiumPoolGuardian:    raydium,
		WalletlessClaimShield:  shield,
		CustomerSummary:        summary,
		CustomerRecommendation: final.Recommendation,
		Metadata: map[string]any{
			"brand":                 "Koschei Web3 Hub",
			"sub_product":           "Security Radar",
			"mode":                  req.Mode,
			"provider":              SecurityRadarProvider,
			"watch_mode":            SecurityRadarWatchMode,
			"rule_version":          SecurityRadarRuleVersion,
			"final_grade":           final.Grade,
			"final_risk_index":      final.RiskIndex,
			"final_risk_level":      final.RiskLevel,
			"final_recommendation":  final.Recommendation,
			"deterministic_scoring": false,
			"ai_final_scoring":      false,
			"score_source":          "live_solana_rpc_evidence",
			"data_quality":          profile.DataQuality,
			"evidence_status":       profile.EvidenceStatus,
		},
	}
}

func FinalSecurityRadarVerdict(bundle SecurityRadarBundle) SecurityRadarFinalVerdict {
	winner := bundle.PumpSybilRadar
	for _, verdict := range []SecurityRadarVerdict{bundle.RaydiumPoolGuardian} {
		if verdict.RiskIndex > winner.RiskIndex {
			winner = verdict
		}
	}
	return SecurityRadarFinalVerdict{
		Grade:          winner.Grade,
		RiskIndex:      winner.RiskIndex,
		RiskLevel:      winner.RiskLevel,
		Verdict:        winner.Verdict,
		Recommendation: winner.Recommendation,
		RuleVersion:    SecurityRadarRuleVersion,
		Signed:         true,
		Signature:      winner.Signature,
	}
}

func collectRadarEvidence(req SecurityRadarRequest) radarEvidenceProfile {
	return collectRadarEvidenceContext(context.Background(), req)
}

func collectRadarEvidenceContext(parent context.Context, req SecurityRadarRequest) radarEvidenceProfile {
	if parent == nil {
		parent = context.Background()
	}
	profile := radarEvidenceProfile{Target: req.Target, Network: req.Network, DataQuality: "no_rpc_evidence", EvidenceStatus: "insufficient_evidence"}
	rpcURL := strings.TrimSpace(os.Getenv("SOLANA_RPC_URL"))
	if rpcURL == "" {
		profile.Errors = append(profile.Errors, "SOLANA_RPC_URL is not configured")
		return profile
	}
	profile.RPCConfigured = true
	if strings.TrimSpace(req.Target) == "" {
		profile.Errors = append(profile.Errors, "target is empty")
		return profile
	}

	timeout := 6500 * time.Millisecond
	modeLower := strings.ToLower(req.Mode)
	if strings.Contains(modeLower, "owner") || strings.Contains(modeLower, "manual") || strings.Contains(modeLower, "live_stream:"+ModulePumpSybilRadar) {
		timeout = 18 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()

	if account, err := SolanaGetAccountInfoJSONParsed(ctx, rpcURL, req.Target); err == nil && account.Value != nil {
		profile.LiveRPC = true
		profile.AccountExists = true
		profile.AccountOwner = strings.TrimSpace(account.Value.Owner)
		profile.AccountExecutable = account.Value.Executable
		applyParsedMintInfo(&profile, account.Value.Data)
	} else if err != nil {
		profile.Errors = append(profile.Errors, compactRadarError("getAccountInfo", err))
	}

	if supply, err := SolanaGetTokenSupply(ctx, rpcURL, req.Target); err == nil {
		profile.LiveRPC = true
		profile.IsTokenMint = true
		profile.TokenSupply = solanaTokenFloat(supply.Value)
	} else {
		profile.Errors = append(profile.Errors, compactRadarError("getTokenSupply", err))
	}

	if largest, err := SolanaGetTokenLargestAccounts(ctx, rpcURL, req.Target); err == nil {
		profile.LiveRPC = true
		profile.IsTokenMint = true
		profile.LargestAccounts = len(largest.Value)
		applyLargestHolderEvidence(&profile, largest.Value)
		profile.RawLargestHolderPct = profile.LargestHolderPct
		profile.RawTop10HolderPct = profile.Top10HolderPct
		profile.HolderRoles = AnalyzeSolanaHolderRoles(ctx, rpcURL, profile.TokenSupply, largest.Value)
		if profile.HolderRoles.Available && profile.HolderRoles.RoleAdjusted && !profile.HolderRoles.BlockingEvidenceGap {
			profile.LargestHolderPct = int(math.Round(profile.HolderRoles.EffectiveTop1Percentage))
			profile.Top10HolderPct = int(math.Round(profile.HolderRoles.EffectiveTop10Percentage))
		}
		if profile.HolderRoles.BlockingEvidenceGap {
			profile.DataQuality = "partial_rpc_evidence"
			profile.EvidenceStatus = "dominant_holder_role_unresolved"
		}
	} else {
		profile.Errors = append(profile.Errors, compactRadarError("getTokenLargestAccounts", err))
	}

	if signatures, err := SolanaGetSignaturesForAddress(ctx, rpcURL, req.Target, 100); err == nil {
		profile.LiveRPC = true
		profile.RecentSignatureCount = len(signatures)
		profile.TargetSignatureHistoryExhausted = len(signatures) < 100
		if len(signatures) > 0 {
			profile.LatestSignature = signatures[0].Signature
			profile.LatestSlot = signatures[0].Slot
		}
		var newest, oldest int64
		for i, sig := range signatures {
			if sig.Err != nil {
				profile.FailedSignatureCount++
			}
			if sig.BlockTime != nil && *sig.BlockTime > 0 {
				if i == 0 || *sig.BlockTime > newest {
					newest = *sig.BlockTime
				}
				if oldest == 0 || *sig.BlockTime < oldest {
					oldest = *sig.BlockTime
					profile.TargetOldestSlot = sig.Slot
				}
			}
		}
		if newest > 0 && oldest > 0 && newest >= oldest {
			profile.TargetSignatureTimingObserved = true
			profile.SignatureWindowSeconds = newest - oldest
			profile.TargetOldestBlockTime = oldest
		}
	} else {
		profile.Errors = append(profile.Errors, compactRadarError("getSignaturesForAddress", err))
	}

	if profile.IsTokenMint && profile.HolderRoles.Available {
		profile.HolderCluster = AnalyzeSolanaHolderCluster(ctx, rpcURL, req.Target, profile.HolderRoles, profile.TargetOldestBlockTime, profile.TargetOldestSlot)
		if store := securityRadarStoreFromContext(ctx); store != nil {
			_ = store.CaptureFundingClusters(ctx, req.Target, req.Network, profile.HolderCluster)
			if recurrence, err := store.LoadFundingRecurrence(ctx, req.Target, req.Network, profile.HolderCluster); err == nil {
				profile.FundingRecurrence = recurrence
			} else {
				profile.FundingRecurrence = FundingRecurrenceAnalysis{
					Status: "unavailable", EvidenceStatus: "unavailable", CurrentTarget: req.Target, Network: normalizeRadarNetwork(req.Network),
					Sources: []FundingSourceRecurrence{}, Limitations: []string{"Funding corpus read failed after holder-cluster persistence."},
				}
			}
		}
	}

	if profile.LiveRPC {
		profile.DataQuality = "live_rpc_evidence"
		profile.EvidenceStatus = "verified_rpc_observation"
		if !profile.IsTokenMint {
			profile.DataQuality = "partial_rpc_evidence"
			profile.EvidenceStatus = "target_not_confirmed_as_token_mint"
		}
	}
	return profile
}

func buildPumpSybilVerdict(req SecurityRadarRequest, profile radarEvidenceProfile, generatedAt string) SecurityRadarVerdict {
	risk := 18
	if !profile.LiveRPC {
		risk = 28
	} else {
		risk += burstRisk(profile.RecentSignatureCount, profile.SignatureWindowSeconds)
		risk += concentrationRisk(profile.LargestHolderPct, profile.Top10HolderPct)
		if profile.FailedSignatureCount >= 10 {
			risk += 6
		}
	}
	risk = clampRisk(risk)

	signals := baseEvidenceSignals(profile)
	signals["pump_fun_sybil_score"] = risk
	signals["recent_signature_count"] = profile.RecentSignatureCount
	signals["signature_window_seconds"] = profile.SignatureWindowSeconds
	signals["largest_holder_percentage"] = profile.LargestHolderPct
	signals["top_10_holder_percentage"] = profile.Top10HolderPct
	signals["failed_signature_count"] = profile.FailedSignatureCount
	signals["buyer_cluster_graph_available"] = false
	signals["creator_link_graph_available"] = false
	signals["intelligence_gap"] = "first_buyer_and_funding_graph_requires_parsed_launch_transactions"

	evidence := []string{
		"Live Solana RPC evidence is used for transaction burst and holder concentration checks when available.",
		fmt.Sprintf("Recent signatures observed: %d; observation window: %ds.", profile.RecentSignatureCount, profile.SignatureWindowSeconds),
		fmt.Sprintf("Holder concentration: largest=%d%% top10=%d%% across %d largest token accounts.", profile.LargestHolderPct, profile.Top10HolderPct, profile.LargestAccounts),
		"Buyer-cluster and creator-funding links are not claimed unless parsed launch transaction evidence is present.",
	}
	if !profile.LiveRPC {
		evidence = []string{"No live Solana RPC evidence was collected; Koschei refuses to claim sybil detection from hash/random scoring.", "Verdict is conservative until signatures, holder concentration and launch transaction graph are available."}
	}
	return newRadarVerdict("Pump.fun Sybil Radar", ModulePumpSybilRadar, req, risk, signals, evidence, generatedAt)
}

func buildRaydiumPoolVerdict(req SecurityRadarRequest, profile radarEvidenceProfile, generatedAt string) SecurityRadarVerdict {
	risk := 18
	if !profile.LiveRPC {
		risk = 28
	} else {
		if profile.MintAuthorityPresent {
			risk += 22
		}
		if profile.FreezeAuthorityPresent {
			risk += 22
		}
		risk += concentrationRisk(profile.LargestHolderPct, profile.Top10HolderPct)
		if profile.AccountExecutable {
			risk += 8
		}
		if !profile.IsTokenMint {
			risk += 8
		}
	}
	risk = clampRisk(risk)

	signals := baseEvidenceSignals(profile)
	signals["pool_risk"] = risk
	signals["mint_authority_present"] = profile.MintAuthorityPresent
	signals["freeze_authority_present"] = profile.FreezeAuthorityPresent
	signals["largest_holder_percentage"] = profile.LargestHolderPct
	signals["top_10_holder_percentage"] = profile.Top10HolderPct
	signals["token_supply"] = profile.TokenSupply
	signals["account_owner"] = profile.AccountOwner

	evidence := []string{
		"Live Solana RPC evidence is used for token authority and holder concentration checks when available.",
		fmt.Sprintf("Mint authority present: %t; freeze authority present: %t.", profile.MintAuthorityPresent, profile.FreezeAuthorityPresent),
		fmt.Sprintf("Largest holder=%d%%; top10 holders=%d%%; token supply observed=%.4f.", profile.LargestHolderPct, profile.Top10HolderPct, profile.TokenSupply),
	}
	if !profile.LiveRPC {
		evidence = []string{"No live Solana RPC evidence was collected; pool authority and liquidity risk cannot be asserted.", "Verdict is conservative until token account, supply and holder concentration evidence are available."}
	}
	return newRadarVerdict("Raydium Pool Guardian", ModuleRaydiumPoolGuardian, req, risk, signals, evidence, generatedAt)
}

func buildClaimShieldVerdict(req SecurityRadarRequest, profile radarEvidenceProfile, generatedAt string) SecurityRadarVerdict {
	signals := baseEvidenceSignals(profile)
	signals["internal_only"] = true
	signals["customer_surface"] = false
	evidence := []string{"Walletless Claim Shield is kept as internal pre-connect evidence and does not drive the customer-facing final Security Radar grade."}
	return newRadarVerdict("Walletless Claim Shield", ModuleWalletlessClaimShield, req, 1, signals, evidence, generatedAt)
}

func newRadarVerdict(module, moduleID string, req SecurityRadarRequest, risk int, signals map[string]any, evidence []string, generatedAt string) SecurityRadarVerdict {
	level := riskLevelFromIndex(risk)
	verdict := verdictFromRiskLevel(moduleID, level, signals)
	recommendation := recommendationFromRiskLevel(level)
	v := SecurityRadarVerdict{
		Module:         module,
		ModuleID:       moduleID,
		Target:         req.Target,
		Network:        req.Network,
		Grade:          gradeFromRiskLevel(level),
		RiskIndex:      risk,
		RiskLevel:      level,
		Verdict:        verdict,
		Recommendation: recommendation,
		Signals:        signals,
		Evidence:       evidence,
		GeneratedAt:    generatedAt,
		RuleVersion:    SecurityRadarRuleVersion,
		Signed:         true,
	}
	v.Signature = signSecurityRadarVerdict(v.ModuleID, v.Target, v.Network, v.RiskIndex)
	return v
}

func baseEvidenceSignals(profile radarEvidenceProfile) map[string]any {
	return map[string]any{
		"provider":                      SecurityRadarProvider,
		"watch_mode":                    SecurityRadarWatchMode,
		"score_source":                  "live_solana_rpc_evidence",
		"real_onchain_evidence":         profile.LiveRPC,
		"data_quality":                  profile.DataQuality,
		"evidence_status":               profile.EvidenceStatus,
		"deterministic_preview":         false,
		"rpc_configured":                profile.RPCConfigured,
		"account_exists":                profile.AccountExists,
		"is_token_mint":                 profile.IsTokenMint,
		"largest_holder_percentage":     profile.LargestHolderPct,
		"top_10_holder_percentage":      profile.Top10HolderPct,
		"raw_largest_holder_percentage": profile.RawLargestHolderPct,
		"raw_top_10_holder_percentage":  profile.RawTop10HolderPct,
		"holder_role_analysis":          profile.HolderRoles,
		"holder_role_adjusted":          profile.HolderRoles.RoleAdjusted,
		"holder_role_blocking_gap":      profile.HolderRoles.BlockingEvidenceGap,
		"latest_signature":              profile.LatestSignature,
		"latest_slot":                   profile.LatestSlot,
		"rpc_errors":                    profile.Errors,
	}
}

func applyParsedMintInfo(profile *radarEvidenceProfile, raw any) {
	data, ok := raw.(map[string]any)
	if !ok {
		return
	}
	parsed, ok := data["parsed"].(map[string]any)
	if !ok {
		return
	}
	if strings.EqualFold(anyString(parsed["type"]), "mint") {
		profile.IsTokenMint = true
	}
	info, ok := parsed["info"].(map[string]any)
	if !ok {
		return
	}
	mintAuthority := strings.TrimSpace(anyString(info["mintAuthority"]))
	freezeAuthority := strings.TrimSpace(anyString(info["freezeAuthority"]))
	profile.MintAuthorityPresent = mintAuthority != ""
	profile.FreezeAuthorityPresent = freezeAuthority != ""
}

func applyLargestHolderEvidence(profile *radarEvidenceProfile, accounts []SolanaLargestTokenAccount) {
	if len(accounts) == 0 {
		return
	}
	values := make([]float64, 0, len(accounts))
	total := 0.0
	for _, account := range accounts {
		v := solanaTokenFloat(account.SolanaTokenAmount)
		if v < 0 {
			v = 0
		}
		values = append(values, v)
		total += v
	}
	if total <= 0 {
		if profile.TokenSupply > 0 {
			total = profile.TokenSupply
		} else {
			return
		}
	}
	largest := 0.0
	top10 := 0.0
	for i, v := range values {
		if i == 0 {
			largest = v
		}
		if i < 10 {
			top10 += v
		}
	}
	profile.LargestHolderPct = int(math.Round((largest / total) * 100))
	profile.Top10HolderPct = int(math.Round((top10 / total) * 100))
}

func burstRisk(count int, windowSeconds int64) int {
	risk := 0
	switch {
	case count >= 90:
		risk += 25
	case count >= 50:
		risk += 18
	case count >= 20:
		risk += 10
	case count >= 8:
		risk += 5
	}
	if count >= 25 && windowSeconds > 0 && windowSeconds <= 180 {
		risk += 20
	} else if count >= 15 && windowSeconds > 0 && windowSeconds <= 600 {
		risk += 10
	}
	return risk
}

func concentrationRisk(largestPct, top10Pct int) int {
	risk := 0
	switch {
	case largestPct >= 60:
		risk += 28
	case largestPct >= 35:
		risk += 20
	case largestPct >= 20:
		risk += 10
	}
	switch {
	case top10Pct >= 90:
		risk += 22
	case top10Pct >= 75:
		risk += 14
	case top10Pct >= 55:
		risk += 8
	}
	return risk
}

func clampRisk(risk int) int {
	if risk < 1 {
		return 1
	}
	if risk > 95 {
		return 95
	}
	return risk
}

func compactRadarError(method string, err error) string {
	if err == nil {
		return ""
	}
	msg := strings.TrimSpace(err.Error())
	if len(msg) > 180 {
		msg = msg[:180]
	}
	return method + ": " + msg
}

func anyString(v any) string {
	if v == nil {
		return ""
	}
	switch x := v.(type) {
	case string:
		return x
	case fmt.Stringer:
		return x.String()
	default:
		return fmt.Sprint(v)
	}
}

func riskLevelFromIndex(idx int) string {
	switch {
	case idx >= 85:
		return "critical"
	case idx >= 65:
		return "high"
	case idx >= 35:
		return "medium"
	default:
		return "low"
	}
}

func gradeFromRiskLevel(level string) string {
	switch level {
	case "critical":
		return "F"
	case "high":
		return "D"
	case "medium":
		return "B"
	default:
		return "A"
	}
}

func recommendationFromRiskLevel(level string) string {
	switch level {
	case "critical":
		return "avoid"
	case "high":
		return "manual_review"
	case "medium":
		return "watch"
	default:
		return "safe_to_monitor"
	}
}

func verdictFromRiskLevel(moduleID, level string, signals map[string]any) string {
	if ok, _ := signals["real_onchain_evidence"].(bool); !ok && moduleID != ModuleWalletlessClaimShield {
		return "Insufficient live on-chain evidence; no sybil or pool-risk claim asserted"
	}
	switch moduleID {
	case ModulePumpSybilRadar:
		switch level {
		case "critical":
			return "Critical launch concentration and burst activity observed"
		case "high":
			return "High-risk launch concentration requires manual review"
		case "medium":
			return "Moderate launch risk observed from live Solana evidence"
		default:
			return "No critical launch sybil evidence observed"
		}
	case ModuleRaydiumPoolGuardian:
		switch level {
		case "critical":
			return "Critical token authority or concentration risk observed"
		case "high":
			return "High pool or token authority risk requires review"
		case "medium":
			return "Pool requires liquidity, authority and holder monitoring"
		default:
			return "No critical Raydium pool evidence observed"
		}
	default:
		return "Internal pre-connect evidence only"
	}
}

func signSecurityRadarVerdict(moduleID, target, network string, riskIndex int) string {
	payload := fmt.Sprintf("%s|%s|%s|%d|%s", moduleID, strings.TrimSpace(target), strings.TrimSpace(network), riskIndex, SecurityRadarRuleVersion)
	h := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(h[:])
}
