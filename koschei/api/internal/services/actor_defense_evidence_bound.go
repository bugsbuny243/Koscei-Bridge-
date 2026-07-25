package services

import (
	"fmt"
	"strings"
)

// EvaluateEvidenceBoundActorDefenseRules applies the actor ruleset and then
// enforces the public acceptance invariant: every grade-changing rule must be
// backed by at least one canonical evidence key. Track counters may remain
// visible as watch context, but they cannot issue a letter grade by themselves.
func EvaluateEvidenceBoundActorDefenseRules(track ActorDefenseTrack, evidence []ActorDefenseEvidenceRecord) ActorDefenseRuleVerdict {
	verdict := EvaluateActorDefenseRules(track, evidence)
	return bindActorDefenseRuleEvidence(track, evidence, verdict)
}

func bindActorDefenseRuleEvidence(track ActorDefenseTrack, evidence []ActorDefenseEvidenceRecord, verdict ActorDefenseRuleVerdict) ActorDefenseRuleVerdict {
	triggered := make([]ActorDefenseRuleHit, 0, len(verdict.TriggeredRules))
	watch := append([]ActorDefenseRuleHit{}, verdict.WatchFlags...)

	for _, hit := range verdict.TriggeredRules {
		hit.EvidenceKeys = actorRuleUniqueStrings(hit.EvidenceKeys)
		hit.Signatures = actorRuleUniqueStrings(hit.Signatures)
		if len(hit.EvidenceKeys) == 0 {
			keys, signatures := actorDefenseEvidenceForRule(hit.RuleID, evidence)
			hit.EvidenceKeys = keys
			hit.Signatures = signatures
		}
		if len(hit.EvidenceKeys) == 0 {
			hit.Tier = "watch"
			hit.EvidenceStatus = "unverified"
			hit.GradeCap = ""
			hit.GradeEffect = "none"
			hit.Summary = strings.TrimSpace(hit.Summary) + " Canonical evidence references are missing, so this observation is excluded from the grade."
			watch = append(watch, hit)
			continue
		}
		triggered = append(triggered, hit)
	}

	actorRuleSortHits(triggered)
	watch = actorRuleMergeHits(watch)
	verdict.TriggeredRules = triggered
	verdict.WatchFlags = watch
	verdict.Grade, verdict.Verdict, verdict.DecisionPath = evidenceBoundActorDecision(triggered, watch)
	verdict.Signed = false
	verdict.Signature = ""
	if verdict.Grade != "-" && len(triggered) > 0 {
		verdict.Signed = true
		verdict.Signature = signActorDefenseRuleVerdict(track, verdict)
	}
	return verdict
}

func actorDefenseEvidenceForRule(ruleID string, evidence []ActorDefenseEvidenceRecord) ([]string, []string) {
	allowed := map[string]bool{}
	switch strings.TrimSpace(ruleID) {
	case ActorRuleCompoundCreatorReuse:
		allowed["created_token"] = true
	case ActorRuleCompoundHolderReuse:
		allowed["dominant_holder_reuse"] = true
		allowed["dominant_holder_recurrence"] = true
	case ActorRuleCompoundRelatedActorReuse:
		allowed["cross_token_related_actor"] = true
		allowed["cross_token_creator_holder_transfer"] = true
		allowed["dominant_holder_reuse"] = true
		allowed["dominant_holder_recurrence"] = true
	default:
		return nil, nil
	}

	keys := []string{}
	signatures := []string{}
	for _, item := range evidence {
		if !allowed[strings.ToLower(strings.TrimSpace(item.Relation))] {
			continue
		}
		status := normalizeActorEvidenceStatus(item.VerificationStatus)
		if status != "verified" && status != "observed" {
			continue
		}
		if key := strings.TrimSpace(item.EvidenceKey); key != "" {
			keys = append(keys, key)
		}
		if signature := strings.TrimSpace(item.Signature); signature != "" {
			signatures = append(signatures, signature)
		}
	}
	return actorRuleUniqueStrings(keys), actorRuleUniqueStrings(signatures)
}

func evidenceBoundActorDecision(triggered, watch []ActorDefenseRuleHit) (string, string, []string) {
	hard := []ActorDefenseRuleHit{}
	compound := []ActorDefenseRuleHit{}
	for _, hit := range triggered {
		switch strings.TrimSpace(hit.Tier) {
		case "hard_trigger":
			hard = append(hard, hit)
		case "compounding":
			compound = append(compound, hit)
		}
	}

	decision := []string{
		"Only rules with canonical evidence references may change the grade.",
		"INFERRED and evidence-less observations remain watch-only.",
		"UNVERIFIED evidence is excluded from the verdict.",
	}
	if len(hard) > 0 {
		grade := actorRuleWorstGradeCap(hard)
		decision = append(decision, fmt.Sprintf("Evidence-backed hard-trigger ceiling applied: grade %s.", grade))
		return grade, "hard_trigger", decision
	}
	if len(compound) >= 2 {
		decision = append(decision, "Two or more distinct evidence-backed VERIFIED/OBSERVED compounding rules lowered the baseline by one grade to B.")
		return "B", "compounding_rule", decision
	}
	if len(compound) == 1 {
		decision = append(decision, "Only one evidence-backed compounding observation remains; no letter grade is issued.")
		return "-", "single_observation", decision
	}
	if len(watch) > 0 {
		decision = append(decision, "Only watch flags remain; no letter grade is issued.")
		return "-", "watch_only", decision
	}
	decision = append(decision, "No evidence-backed grade-changing rule was satisfied; absence of evidence is not an A grade.")
	return "-", "no_grade_trigger", decision
}
