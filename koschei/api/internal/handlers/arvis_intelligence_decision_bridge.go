package handlers

import (
	"fmt"
	"sort"
	"strings"

	"koschei/api/internal/services"
)

type intelligenceDecisionRule struct {
	RuleID         string
	EvidenceStatus string
	EvidenceKeys   []string
	Signatures     []string
}

// applyArvisIntelligenceDecision closes the chain-neutral investigation with a
// decision only when the existing signed ARVIS verdict can be linked back to
// canonical evidence for every grade-determining rule. It never re-grades the
// target, predicts intent or treats a signed no-grade result as a safety claim.
func applyArvisIntelligenceDecision(investigation *services.IntelligenceInvestigation, final services.UnifiedRadarVerdict) {
	if investigation == nil || len(investigation.Subjects) == 0 {
		return
	}
	if investigation.Subjects[0].ChainFamily != services.IntelligenceChainFamilySolana {
		return
	}
	if !final.Signed || strings.TrimSpace(final.Grade) == "" || strings.TrimSpace(final.Grade) == "-" {
		return
	}

	rules := intelligenceGradeDeterminingRules(final)
	if len(rules) == 0 {
		return
	}

	refs := []string{}
	missing := []string{}
	allVerified := true
	for _, rule := range rules {
		matched, verified := intelligenceDecisionEvidenceRefs(investigation.Evidence, rule)
		if len(matched) == 0 {
			missing = append(missing, rule.RuleID)
			continue
		}
		refs = append(refs, matched...)
		if !verified || !strings.EqualFold(rule.EvidenceStatus, services.IntelligenceEvidenceVerified) {
			allVerified = false
		}
	}
	refs = uniqueStringsSorted(refs)
	sort.Strings(missing)

	if len(missing) > 0 {
		reasons := append([]string{}, final.DecisionPath...)
		reasons = append(reasons, "Canonical evidence linkage is missing for grade-determining rule IDs: "+strings.Join(missing, ", ")+".")
		investigation.Decision = services.IntelligenceDecision{
			Status:       services.IntelligenceEvidenceUnverified,
			Action:       "investigate",
			Summary:      "A signed deterministic ARVIS verdict exists, but the chain-neutral decision is withheld until every grade-determining rule is linked to canonical evidence.",
			Reasons:      reasons,
			EvidenceRefs: refs,
			Confidence:   0,
		}
		return
	}

	status := services.IntelligenceEvidenceObserved
	if allVerified {
		status = services.IntelligenceEvidenceVerified
	}
	investigation.Decision = services.IntelligenceDecision{
		Status:       status,
		Action:       "review_signed_verdict",
		Summary:      fmt.Sprintf("ARVIS signed deterministic grade %s verdict (%s) is linked to canonical evidence for every grade-determining rule.", strings.TrimSpace(final.Grade), strings.TrimSpace(final.Verdict)),
		Reasons:      append([]string{}, final.DecisionPath...),
		EvidenceRefs: refs,
		Confidence:   1,
	}
}

func attachArvisIntelligenceDecision(assembly *unifiedInvestigationAssembly) {
	if assembly == nil || assembly.Report == nil {
		return
	}
	investigation, ok := assembly.Report["intelligence_contract"].(services.IntelligenceInvestigation)
	if !ok {
		return
	}
	applyArvisIntelligenceDecision(&investigation, assembly.UnifiedVerdict)
	assembly.Report["intelligence_contract"] = investigation
}

func intelligenceGradeDeterminingRules(final services.UnifiedRadarVerdict) []intelligenceDecisionRule {
	eligible := func(hit services.ActorDefenseRuleHit) bool {
		status := strings.ToLower(strings.TrimSpace(hit.EvidenceStatus))
		if status != services.IntelligenceEvidenceVerified && status != services.IntelligenceEvidenceObserved {
			return false
		}
		tier := strings.ToLower(strings.TrimSpace(hit.Tier))
		effect := strings.ToLower(strings.TrimSpace(hit.GradeEffect))
		switch strings.ToLower(strings.TrimSpace(final.Verdict)) {
		case "hard_trigger":
			return tier == "hard_trigger" || strings.HasPrefix(effect, "hard_cap_")
		case "compounding_rule", "severe_compounding_rule":
			return tier == "compounding"
		default:
			return false
		}
	}

	merged := map[string]intelligenceDecisionRule{}
	for _, hit := range final.TriggeredRules {
		if !eligible(hit) {
			continue
		}
		id := strings.TrimSpace(hit.RuleID)
		if id == "" {
			continue
		}
		item := merged[id]
		item.RuleID = id
		if item.EvidenceStatus == "" {
			item.EvidenceStatus = strings.ToLower(strings.TrimSpace(hit.EvidenceStatus))
		} else if !strings.EqualFold(hit.EvidenceStatus, services.IntelligenceEvidenceVerified) {
			item.EvidenceStatus = services.IntelligenceEvidenceObserved
		}
		item.EvidenceKeys = append(item.EvidenceKeys, hit.EvidenceKeys...)
		item.Signatures = append(item.Signatures, hit.Signatures...)
		merged[id] = item
	}

	ids := make([]string, 0, len(merged))
	for id := range merged {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	out := make([]intelligenceDecisionRule, 0, len(ids))
	for _, id := range ids {
		item := merged[id]
		item.EvidenceKeys = uniqueStringsSorted(item.EvidenceKeys)
		item.Signatures = uniqueStringsSorted(item.Signatures)
		out = append(out, item)
	}
	return out
}

func intelligenceDecisionEvidenceRefs(evidence []services.IntelligenceEvidence, rule intelligenceDecisionRule) ([]string, bool) {
	keys := intelligenceDecisionStringSet(rule.EvidenceKeys)
	signatures := intelligenceDecisionStringSet(rule.Signatures)
	refs := []string{}
	allVerified := true
	for _, item := range evidence {
		status := strings.ToLower(strings.TrimSpace(item.Status))
		if status != services.IntelligenceEvidenceVerified && status != services.IntelligenceEvidenceObserved {
			continue
		}
		if !intelligenceEvidenceMatchesDecisionRule(item, rule.RuleID, keys, signatures) {
			continue
		}
		id := strings.TrimSpace(item.ID)
		if id == "" {
			continue
		}
		refs = append(refs, id)
		if status != services.IntelligenceEvidenceVerified {
			allVerified = false
		}
	}
	return uniqueStringsSorted(refs), allVerified
}

func intelligenceEvidenceMatchesDecisionRule(item services.IntelligenceEvidence, ruleID string, keys, signatures map[string]bool) bool {
	if signatures[strings.TrimSpace(item.TransactionHash)] && strings.TrimSpace(item.TransactionHash) != "" {
		return true
	}
	if item.Attributes == nil {
		return false
	}
	if strings.EqualFold(strings.TrimSpace(fmt.Sprint(item.Attributes["rule_id"])), strings.TrimSpace(ruleID)) && strings.TrimSpace(ruleID) != "" {
		return true
	}
	for _, value := range intelligenceAttributeStrings(item.Attributes["evidence_key"]) {
		if keys[value] {
			return true
		}
	}
	for _, value := range intelligenceAttributeStrings(item.Attributes["evidence_keys"]) {
		if keys[value] {
			return true
		}
	}
	for _, value := range intelligenceAttributeStrings(item.Attributes["signatures"]) {
		if signatures[value] {
			return true
		}
	}
	return false
}

func intelligenceAttributeStrings(raw any) []string {
	switch value := raw.(type) {
	case string:
		value = strings.TrimSpace(value)
		if value == "" {
			return nil
		}
		return []string{value}
	case []string:
		return uniqueStringsSorted(value)
	case []any:
		out := make([]string, 0, len(value))
		for _, item := range value {
			if text := strings.TrimSpace(fmt.Sprint(item)); text != "" {
				out = append(out, text)
			}
		}
		return uniqueStringsSorted(out)
	default:
		return nil
	}
}

func intelligenceDecisionStringSet(values []string) map[string]bool {
	out := map[string]bool{}
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" {
			out[value] = true
		}
	}
	return out
}
