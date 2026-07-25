package services

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
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
	actorRuleSortHits(watch)
	verdict.TriggeredRules = triggered
	verdict.WatchFlags = watch
	verdict.Grade, verdict.Verdict, verdict.DecisionPath = evidenceBoundActorDecision(triggered, watch)
	verdict.Signed = evidenceBoundActorDecisionSignable(track, verdict)
	verdict.Signature = ""
	if verdict.Signed {
		verdict.Signature = signEvidenceBoundActorDecision(track, verdict)
	}
	return verdict
}

func evidenceBoundActorDecisionSignable(track ActorDefenseTrack, verdict ActorDefenseRuleVerdict) bool {
	return strings.TrimSpace(track.Network) != "" &&
		strings.TrimSpace(track.TargetKind) != "" &&
		strings.TrimSpace(track.TargetID) != "" &&
		strings.TrimSpace(verdict.RulesetVersion) != "" &&
		strings.TrimSpace(verdict.Verdict) != "" &&
		len(verdict.DecisionPath) > 0
}

// signEvidenceBoundActorDecision signs both letter grades and WITHHOLD states.
// Watch flags and the decision path are included so watch_only,
// single_observation and no_grade_trigger cannot collapse to the same signature.
func signEvidenceBoundActorDecision(track ActorDefenseTrack, verdict ActorDefenseRuleVerdict) string {
	parts := []string{
		strings.TrimSpace(verdict.RulesetVersion),
		strings.TrimSpace(track.Network),
		strings.TrimSpace(track.TargetKind),
		strings.TrimSpace(track.TargetID),
		strings.TrimSpace(verdict.Grade),
		strings.TrimSpace(verdict.Verdict),
	}
	parts = append(parts, evidenceBoundActorHitParts("triggered", verdict.TriggeredRules)...)
	parts = append(parts, evidenceBoundActorHitParts("watch", verdict.WatchFlags)...)
	for _, step := range verdict.DecisionPath {
		parts = append(parts, "decision:"+strings.TrimSpace(step))
	}
	payload := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(payload))
	return "koschei-actor-decision:" + hex.EncodeToString(hash[:])
}

func evidenceBoundActorHitParts(prefix string, hits []ActorDefenseRuleHit) []string {
	parts := make([]string, 0, len(hits))
	for _, hit := range hits {
		parts = append(parts, strings.Join([]string{
			prefix,
			strings.TrimSpace(hit.RuleID),
			strings.TrimSpace(hit.Tier),
			strings.TrimSpace(hit.EvidenceStatus),
			strings.TrimSpace(hit.GradeCap),
			strings.TrimSpace(hit.GradeEffect),
			fmt.Sprint(hit.Count),
			strings.Join(actorRuleUniqueStrings(hit.EvidenceKeys), ","),
			strings.Join(actorRuleUniqueStrings(hit.Signatures), ","),
		}, ":"))
	}
	sort.Strings(parts)
	return parts
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
