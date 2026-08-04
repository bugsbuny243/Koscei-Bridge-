package services

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const UnifiedRadarDecisionContractVersion = "koschei-unified-radar-decision-v1.0.2"

// FinalizeUnifiedRadarVerdictContract binds the deterministic verdict state to
// its target before persistence. A withheld grade ("-") is still a signed
// deterministic decision: it means no grade-changing rule fired, never A/LOW.
func FinalizeUnifiedRadarVerdictContract(target string, verdict UnifiedRadarVerdict) UnifiedRadarVerdict {
	verdict = normalizeUnifiedRadarVerdictDecision(verdict)
	if strings.TrimSpace(verdict.RulesetVersion) == "" {
		verdict.RulesetVersion = UnifiedRadarRulesetVersion
	}
	if verdict.GeneratedAt.IsZero() {
		verdict.GeneratedAt = time.Now().UTC()
	} else {
		verdict.GeneratedAt = verdict.GeneratedAt.UTC()
	}
	verdict.TriggeredRules = nonNilActorRuleHits(verdict.TriggeredRules)
	verdict.WatchFlags = nonNilActorRuleHits(verdict.WatchFlags)
	verdict.DecisionPath = nonNilStrings(verdict.DecisionPath)
	verdict.Signed = true
	// Always recompute after normalization. A previously signed verdict may have
	// counted multiple evidence groups for one rule ID and therefore bound the
	// wrong grade/verdict state.
	verdict.Signature = signUnifiedRadarVerdict(strings.TrimSpace(target), verdict)
	return verdict
}

func normalizeUnifiedRadarVerdictDecision(verdict UnifiedRadarVerdict) UnifiedRadarVerdict {
	verdict.TriggeredRules = nonNilActorRuleHits(verdict.TriggeredRules)
	verdict.WatchFlags = nonNilActorRuleHits(verdict.WatchFlags)
	actorRuleSortHits(verdict.TriggeredRules)
	actorRuleSortHits(verdict.WatchFlags)

	hardCaps := []string{}
	compoundRuleIDs := map[string]bool{}
	for _, hit := range verdict.TriggeredRules {
		status := normalizeActorEvidenceStatus(hit.EvidenceStatus)
		if status == "verified" {
			if capGrade := unifiedRadarContractHitGradeCap(hit); capGrade != "" {
				hardCaps = append(hardCaps, capGrade)
				continue
			}
		}
		if strings.EqualFold(strings.TrimSpace(hit.Tier), "compounding") &&
			(status == "verified" || status == "observed") {
			if ruleID := strings.TrimSpace(hit.RuleID); ruleID != "" {
				compoundRuleIDs[ruleID] = true
			}
		}
	}

	decision := []string{
		"Unified verdict contract: " + UnifiedRadarDecisionContractVersion + ".",
		"Only distinct VERIFIED/OBSERVED compounding rule IDs may lower the baseline.",
		"Multiple evidence groups for one rule remain separately auditable but count once in the grade decision.",
		"VERIFIED hard-cap grade effects are evaluated before compounding rules.",
		"INFERRED is watch-only and UNVERIFIED cannot change the grade.",
	}
	switch {
	case len(hardCaps) > 0:
		verdict.Grade = unifiedRadarContractWorstGrade(hardCaps)
		verdict.Verdict = "hard_trigger"
		decision = append(decision, fmt.Sprintf("Evidence-backed hard-trigger ceiling applied: grade %s.", verdict.Grade))
	case len(compoundRuleIDs) >= 2:
		verdict.Grade = "B"
		verdict.Verdict = "compounding_rule"
		decision = append(decision, fmt.Sprintf("%d distinct evidence-backed compounding rule IDs lowered the baseline by one grade to B.", len(compoundRuleIDs)))
	case len(compoundRuleIDs) == 1:
		verdict.Grade = "-"
		verdict.Verdict = "single_observation"
		decision = append(decision, "One distinct evidence-backed compounding rule ID is visible; no letter grade is issued.")
	case len(verdict.WatchFlags) > 0:
		verdict.Grade = "-"
		verdict.Verdict = "watch_only"
		decision = append(decision, "Only watch flags are present; no letter grade is issued.")
	default:
		verdict.Grade = "-"
		verdict.Verdict = "no_grade_trigger"
		decision = append(decision, "No evidence-backed grade-changing rule was satisfied; absence of evidence is not an A grade.")
	}
	verdict.DecisionPath = decision
	verdict.Signature = ""
	return verdict
}

func unifiedRadarContractHitGradeCap(hit ActorDefenseRuleHit) string {
	if grade := unifiedRadarContractLetter(hit.GradeCap); grade != "" {
		return grade
	}
	effect := strings.ToUpper(strings.TrimSpace(hit.GradeEffect))
	const prefix = "HARD_CAP_"
	if !strings.HasPrefix(effect, prefix) {
		return ""
	}
	return unifiedRadarContractLetter(strings.TrimPrefix(effect, prefix))
}

func unifiedRadarContractLetter(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	switch value {
	case "A", "B", "C", "D", "E", "F":
		return value
	default:
		return ""
	}
}

func unifiedRadarContractWorstGrade(grades []string) string {
	rank := map[string]int{"A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6}
	worst := "-"
	worstRank := 0
	for _, grade := range grades {
		grade = unifiedRadarContractLetter(grade)
		if rank[grade] > worstRank {
			worst = grade
			worstRank = rank[grade]
		}
	}
	return worst
}

// MarshalJSON is the public signed-verdict adapter. Internal names remain
// available for compatibility, while the canonical OSS/SDK contract receives
// rule_version, evidence, triggered_rules and decision_path. Numeric risk fields
// are deliberately absent.
func (verdict UnifiedRadarVerdict) MarshalJSON() ([]byte, error) {
	originalGrade := strings.TrimSpace(verdict.Grade)
	originalVerdict := strings.TrimSpace(verdict.Verdict)
	contract := normalizeUnifiedRadarVerdictDecision(verdict)
	decisionChanged := originalGrade != strings.TrimSpace(contract.Grade) || originalVerdict != strings.TrimSpace(contract.Verdict)
	contract.RulesetVersion = strings.TrimSpace(contract.RulesetVersion)
	if contract.RulesetVersion == "" {
		contract.RulesetVersion = UnifiedRadarRulesetVersion
	}
	if contract.GeneratedAt.IsZero() {
		contract.GeneratedAt = time.Now().UTC()
	} else {
		contract.GeneratedAt = contract.GeneratedAt.UTC()
	}
	contract.TriggeredRules = nonNilActorRuleHits(contract.TriggeredRules)
	contract.WatchFlags = nonNilActorRuleHits(contract.WatchFlags)
	contract.DecisionPath = nonNilStrings(contract.DecisionPath)
	evidence := unifiedVerdictContractEvidence(contract)

	// Some callers evaluate before persistence. The serialized API contract must
	// still be self-consistent. Persistence calls Finalize... with the target and
	// therefore stores the target-bound signature; this fallback signs the
	// deterministic contract state itself when a target-bound signature is not yet
	// attached to the value. A changed decision must never retain its old signature.
	signature := strings.TrimSpace(contract.Signature)
	if decisionChanged {
		signature = ""
	}
	if signature == "" {
		signature = signUnifiedVerdictContractState(contract, evidence)
	}

	payload := struct {
		Grade           string                `json:"grade"`
		Verdict         string                `json:"verdict"`
		Evidence        []string              `json:"evidence"`
		RuleVersion     string                `json:"rule_version"`
		RulesetVersion  string                `json:"ruleset_version,omitempty"`
		ActorRuleset    string                `json:"actor_ruleset_version,omitempty"`
		TriggeredRules  []ActorDefenseRuleHit `json:"triggered_rules"`
		WatchFlags      []ActorDefenseRuleHit `json:"watch_flags,omitempty"`
		DecisionPath    []string              `json:"decision_path"`
		NarrativeSource string                `json:"narrative_source,omitempty"`
		Signed          bool                  `json:"signed"`
		Signature       string                `json:"signature,omitempty"`
		CreatedAt       time.Time             `json:"created_at"`
		GeneratedAt     time.Time             `json:"generated_at,omitempty"`
	}{
		Grade:           normalizeUnifiedContractGrade(contract.Grade),
		Verdict:         strings.TrimSpace(contract.Verdict),
		Evidence:        evidence,
		RuleVersion:     contract.RulesetVersion,
		RulesetVersion:  contract.RulesetVersion,
		ActorRuleset:    strings.TrimSpace(contract.ActorRuleset),
		TriggeredRules:  contract.TriggeredRules,
		WatchFlags:      contract.WatchFlags,
		DecisionPath:    contract.DecisionPath,
		NarrativeSource: strings.TrimSpace(contract.NarrativeSource),
		Signed:          true,
		Signature:       signature,
		CreatedAt:       contract.GeneratedAt,
		GeneratedAt:     contract.GeneratedAt,
	}
	return json.Marshal(payload)
}

func unifiedVerdictContractEvidence(verdict UnifiedRadarVerdict) []string {
	values := []string{}
	for _, hit := range verdict.TriggeredRules {
		status := strings.ToUpper(strings.TrimSpace(hit.EvidenceStatus))
		line := strings.TrimSpace(hit.Summary)
		if line == "" {
			line = "Deterministic rule triggered."
		}
		values = append(values, fmt.Sprintf("%s [%s, %s]: %s", firstNonEmptyUnifiedContract(hit.Title, "Rule"), strings.TrimSpace(hit.RuleID), status, line))
	}
	for _, hit := range verdict.WatchFlags {
		line := strings.TrimSpace(hit.Summary)
		if line == "" {
			line = "Watch-only inference observed."
		}
		values = append(values, fmt.Sprintf("WATCH %s [%s, INFERRED]: %s", firstNonEmptyUnifiedContract(hit.Title, "Rule"), strings.TrimSpace(hit.RuleID), line))
	}
	if len(values) == 0 {
		values = append(values, "No grade-changing rule was triggered; absence of evidence is not an A grade.")
	}
	return uniqueUnifiedContractStrings(values)
}

func signUnifiedVerdictContractState(verdict UnifiedRadarVerdict, evidence []string) string {
	rules := make([]string, 0, len(verdict.TriggeredRules))
	for _, hit := range verdict.TriggeredRules {
		rules = append(rules, strings.TrimSpace(hit.RuleID)+":"+strings.TrimSpace(hit.EvidenceStatus))
	}
	sort.Strings(rules)
	payload := struct {
		Grade       string   `json:"grade"`
		RuleVersion string   `json:"rule_version"`
		Rules       []string `json:"rules"`
		Evidence    []string `json:"evidence"`
		Decision    []string `json:"decision_path"`
	}{
		Grade:       normalizeUnifiedContractGrade(verdict.Grade),
		RuleVersion: strings.TrimSpace(verdict.RulesetVersion),
		Rules:       rules,
		Evidence:    evidence,
		Decision:    nonNilStrings(verdict.DecisionPath),
	}
	raw, _ := json.Marshal(payload)
	sum := sha256.Sum256(raw)
	return "koschei-unified-contract:" + hex.EncodeToString(sum[:])
}

func normalizeUnifiedContractGrade(value string) string {
	value = strings.ToUpper(strings.TrimSpace(value))
	switch value {
	case "A", "B", "C", "D", "E", "F", "-":
		return value
	default:
		return "-"
	}
}

func uniqueUnifiedContractStrings(values []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" || seen[value] {
			continue
		}
		seen[value] = true
		out = append(out, value)
	}
	return out
}

func firstNonEmptyUnifiedContract(values ...string) string {
	for _, value := range values {
		if value = strings.TrimSpace(value); value != "" {
			return value
		}
	}
	return ""
}
