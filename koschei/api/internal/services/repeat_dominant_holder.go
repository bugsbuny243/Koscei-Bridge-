package services

import (
	"fmt"
	"strings"
	"time"
)

const RepeatDominantObservationDays = 30

type RepeatDominantHolderMatch struct {
	Mint       string  `json:"mint"`
	Percentage float64 `json:"percentage"`
	Rank       int     `json:"rank"`
	ScannedAt  string  `json:"scanned_at"`
}

type RepeatDominantHolderEvidence struct {
	OwnerWallet       string  `json:"owner_wallet"`
	CurrentMint       string  `json:"current_mint"`
	CurrentPercentage float64 `json:"current_percentage"`
	TokenCount        int     `json:"token_count"`
	ObservationDays   int     `json:"observation_days"`
	ObservationWindow string  `json:"observation_window"`
	// Deprecated compatibility diagnostic. It is not consumed by an ARVIS arm
	// or the unified final verdict.
	RiskWeight   int                         `json:"risk_weight,omitempty"`
	Matches      []RepeatDominantHolderMatch `json:"matches"`
	EvidenceLine string                      `json:"evidence_line"`
}

func RepeatDominantRiskWeight(currentPercentage float64, tokenCount int) int {
	if currentPercentage < 20 || tokenCount < 2 {
		return 0
	}
	risk := 55 + int(currentPercentage/5) + (tokenCount-1)*6
	if risk > 90 {
		risk = 90
	}
	if risk < 65 {
		risk = 65
	}
	return risk
}

func RepeatDominantEvidenceLine(owner string, matches []RepeatDominantHolderMatch, days int) string {
	if days <= 0 {
		days = RepeatDominantObservationDays
	}
	items := make([]string, 0, len(matches))
	for _, match := range matches {
		date := strings.TrimSpace(match.ScannedAt)
		if parsed, err := time.Parse(time.RFC3339, date); err == nil {
			date = parsed.UTC().Format("2006-01-02")
		}
		items = append(items, fmt.Sprintf("%s %.2f%% (%s)", repeatDominantShortMint(match.Mint), match.Percentage, date))
	}
	return fmt.Sprintf("REPEAT DOMINANT HOLDER: Bu cüzdan son %d gün Koschei gözleminde %d farklı token'da top-5 holder: %s. Bu yalnızca saklanan zincir üstü holder gözlemlerini bağlar; kimlik veya niyet iddiası değildir.", days, len(matches), strings.Join(items, ", "))
}

func repeatDominantShortMint(mint string) string {
	mint = strings.TrimSpace(mint)
	if len(mint) <= 18 {
		return mint
	}
	return mint[:8] + "…" + mint[len(mint)-6:]
}

func ApplyRepeatDominantHolderEvidenceToHolderIntelligence(in HolderIntelligence, evidence []RepeatDominantHolderEvidence) HolderIntelligence {
	if len(evidence) == 0 {
		return in
	}
	byOwner := map[string]RepeatDominantHolderEvidence{}
	for _, item := range evidence {
		byOwner[strings.TrimSpace(item.OwnerWallet)] = item
		if strings.TrimSpace(item.EvidenceLine) != "" {
			in.Findings = appendUniqueHolderEvidence(in.Findings, item.EvidenceLine)
		}
	}
	for i := range in.Rows {
		item, ok := byOwner[strings.TrimSpace(in.Rows[i].OwnerWallet)]
		if !ok {
			continue
		}
		in.Rows[i].RepeatDominantHolder = true
		in.Rows[i].RepeatDominantTokenCount = item.TokenCount
		in.Rows[i].RepeatDominantObservationWindow = item.ObservationWindow
		in.Rows[i].RepeatDominantRiskWeight = item.RiskWeight
		in.Rows[i].RepeatDominantMatches = append([]RepeatDominantHolderMatch{}, item.Matches...)
		in.Rows[i].Evidence = appendUniqueHolderEvidence(in.Rows[i].Evidence, item.EvidenceLine)
		in.RepeatDominantHolderCount++
	}
	return in
}

// ApplyRepeatDominantHolderEvidenceToAnalysis replaces the dedicated Repeat
// Actor Scan placeholder. A bounded no-match query is represented as completed
// without a finding instead of being mislabeled as missing evidence. It never
// mutates Intelligence Graph or the unified final verdict.
func ApplyRepeatDominantHolderEvidenceToAnalysis(analysis ArvisAnalysis, req SecurityRadarRequest, evidence []RepeatDominantHolderEvidence) ArvisAnalysis {
	lines := []string{}
	owners := []string{}
	maxTokenCount := 0
	for _, item := range evidence {
		if strings.TrimSpace(item.EvidenceLine) != "" {
			lines = append(lines, item.EvidenceLine)
		}
		if strings.TrimSpace(item.OwnerWallet) != "" {
			owners = append(owners, item.OwnerWallet)
		}
		if item.TokenCount > maxTokenCount {
			maxTokenCount = item.TokenCount
		}
	}
	generatedAt := time.Now().UTC().Format(time.RFC3339)
	findingObserved := len(evidence) > 0
	signals := map[string]any{
		"module_id":                        ModuleRepeatActorScan,
		"real_onchain_evidence":            true,
		"stored_scan_evidence":             true,
		"evidence_status":                  "observed",
		"execution_status":                 ArvisExecutionCompleted,
		"collector_attempted":              true,
		"applicable":                       true,
		"finding_observed":                 findingObserved,
		"repeat_dominant_holder":           findingObserved,
		"repeat_dominant_holders":          evidence,
		"repeat_dominant_owner_wallets":    owners,
		"repeat_dominant_observation_days": RepeatDominantObservationDays,
		"max_repeat_token_count":           maxTokenCount,
		"persistent_actor_index":           true,
		"identity_or_intent_claim":         false,
		"numeric_score_disabled":           true,
		"grade_effect":                     "none_at_arm_layer",
	}
	if !findingObserved {
		lines = append(lines, fmt.Sprintf("Koschei persistent holder memory was queried for the bounded %d-day observation window; no repeat-dominant holder match was observed. This bounded negative finding is not a safety claim.", RepeatDominantObservationDays))
		signals["evidence_status"] = "observed_no_repeat_match"
	}
	repeatArm := evidenceArm("Repeat Actor Scan", ModuleRepeatActorScan, req, 0, signals, lines, generatedAt)
	if findingObserved {
		repeatArm.Verdict = "Aynı zincir üstü holder cüzdanı, Koschei'nin kalıcı gözlem hafızasında birden fazla tokenda baskın owner olarak gözlendi."
		repeatArm.Recommendation = "Use the unified rules engine to combine repeat-actor evidence with creator, funding, holder and liquidity evidence."
	} else {
		repeatArm.Verdict = "Persistent actor-memory query completed; no repeat-dominant holder match was observed in the bounded evidence window."
		repeatArm.Recommendation = "Continue persistent observation; absence inside the bounded window is not proof of absence outside it."
	}

	arms := ArvisArmsFromBundle(analysis.Bundle)
	if len(arms) == 0 {
		arms = append([]SecurityRadarVerdict{}, analysis.Arms...)
	}
	updated := make([]SecurityRadarVerdict, 0, len(arms))
	found := false
	for _, arm := range arms {
		if arm.ModuleID == ModuleRepeatActorScan {
			updated = append(updated, repeatArm)
			found = true
			continue
		}
		updated = append(updated, arm)
	}
	if !found {
		updated = append(updated, repeatArm)
	}
	analysis.Arms = updated
	analysis.Final = arvisCompatibilityFinal()
	if analysis.Bundle.Metadata == nil {
		analysis.Bundle.Metadata = map[string]any{}
	}
	analysis.Bundle.Metadata["arvis_arms"] = updated
	analysis.Bundle.Metadata["repeat_dominant_holders"] = evidence
	analysis.Bundle.Metadata["repeat_dominant_holder_count"] = len(evidence)
	analysis.Bundle.Metadata["verified_arm_count"] = verifiedArvisEvidenceCount(updated)
	analysis.Bundle.Metadata["runtime_arm_count"] = verifiedArvisEvidenceCount(updated)
	analysis.Bundle.Metadata["final_verdict_source"] = "EvaluateUnifiedRadarVerdict"
	if findingObserved {
		analysis.Bundle.CustomerSummary = fmt.Sprintf("ARVIS connected %d repeat-dominant holder observation(s) from persistent Koschei actor memory.", len(evidence))
	} else {
		analysis.Bundle.CustomerSummary = fmt.Sprintf("ARVIS completed the %d-day persistent holder-memory query without a repeat-dominant match.", RepeatDominantObservationDays)
	}
	analysis.Bundle.CustomerRecommendation = "evaluate_unified_rules"
	return ApplyArvisInvestigationCoverage(analysis)
}
