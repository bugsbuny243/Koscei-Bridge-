package services

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"
)

const ActorDefenseRulesetVersion = "koschei-actor-defense-rules-v1.0.2"

const (
	ActorRuleHardCreatorLiquidityRemoval = "ARD-H001"
	ActorRuleHardCreatorHolderFunding    = "ARD-H002"
	ActorRuleHardPriorTokenRug           = "ARD-H003"
	ActorRuleCompoundCreatorReuse        = "ARD-C001"
	ActorRuleCompoundHolderReuse         = "ARD-C002"
	ActorRuleCompoundRelatedActorReuse   = "ARD-C003"
	ActorRuleCompoundRepeatedTransfer    = "ARD-C004"
	ActorRuleCompoundObservedRemoval     = "ARD-C005"
	ActorRuleWatchInferredEvidence       = "ARD-W001"
	ActorRuleWatchPossibleDust           = "ARD-W002"
)

type ActorDefenseRuleHit struct {
	RuleID         string         `json:"rule_id"`
	Title          string         `json:"title"`
	Tier           string         `json:"tier"`
	EvidenceStatus string         `json:"evidence_status"`
	GradeCap       string         `json:"grade_cap,omitempty"`
	GradeEffect    string         `json:"grade_effect"`
	Count          int            `json:"count"`
	Summary        string         `json:"summary"`
	EvidenceKeys   []string       `json:"evidence_keys,omitempty"`
	Signatures     []string       `json:"signatures,omitempty"`
	Facts          map[string]any `json:"facts,omitempty"`
}

type ActorDefenseRuleVerdict struct {
	Grade                      string                `json:"grade"`
	Verdict                    string                `json:"verdict"`
	RulesetVersion             string                `json:"ruleset_version"`
	TriggeredRules             []ActorDefenseRuleHit `json:"triggered_rules"`
	WatchFlags                 []ActorDefenseRuleHit `json:"watch_flags"`
	ExcludedUnverifiedEvidence int                   `json:"excluded_unverified_evidence"`
	DecisionPath               []string              `json:"decision_path"`
	NarrativeSource            string                `json:"narrative_source"`
	Signed                     bool                  `json:"signed"`
	Signature                  string                `json:"signature,omitempty"`
	GeneratedAt                time.Time             `json:"generated_at"`
}

type actorRuleDirectTransferGroup struct {
	Relation        string
	CounterpartKind string
	CounterpartID   string
	EvidenceStatus  string
	Signatures      map[string]bool
	EvidenceKeys    map[string]bool
}

// EvaluateActorDefenseRules applies a versioned rule table. It never averages
// evidence classes and never emits a numeric score. VERIFIED may activate hard
// triggers, VERIFIED/OBSERVED may participate in explicit compounding rules,
// INFERRED is watch-only and UNVERIFIED is excluded from the decision.
func EvaluateActorDefenseRules(track ActorDefenseTrack, evidence []ActorDefenseEvidenceRecord) ActorDefenseRuleVerdict {
	now := time.Now().UTC()
	hard := []ActorDefenseRuleHit{}
	compound := []ActorDefenseRuleHit{}
	watch := []ActorDefenseRuleHit{}
	unverified := 0
	directTransfers := map[string]*actorRuleDirectTransferGroup{}

	if track.CreatedTokenCount >= 2 {
		status := actorRuleTrackFactStatus(track.Dossier, "creator_reuse_evidence_status", "observed")
		hit := ActorDefenseRuleHit{
			RuleID: ActorRuleCompoundCreatorReuse, Title: "Creator/deployer reuse",
			Tier: "compounding", EvidenceStatus: status, GradeEffect: "compounding_input",
			Count:   track.CreatedTokenCount,
			Summary: fmt.Sprintf("The same creator/deployer wallet is connected to %d observed tokens.", track.CreatedTokenCount),
			Facts:   map[string]any{"created_token_count": track.CreatedTokenCount},
		}
		actorRulePlaceHit(hit, &compound, &watch, &unverified)
	}
	if track.DominantHolderTokenCount >= 2 {
		status := actorRuleTrackFactStatus(track.Dossier, "holder_reuse_evidence_status", "observed")
		hit := ActorDefenseRuleHit{
			RuleID: ActorRuleCompoundHolderReuse, Title: "Dominant-holder reuse",
			Tier: "compounding", EvidenceStatus: status, GradeEffect: "compounding_input",
			Count:   track.DominantHolderTokenCount,
			Summary: fmt.Sprintf("The same owner-resolved wallet is a dominant holder across %d observed tokens.", track.DominantHolderTokenCount),
			Facts:   map[string]any{"dominant_holder_token_count": track.DominantHolderTokenCount},
		}
		actorRulePlaceHit(hit, &compound, &watch, &unverified)
	}
	if track.RelatedActorCount > 0 && actorDefenseStateRank(track.State) >= actorDefenseStateRank("correlated") {
		status := actorRuleTrackFactStatus(track.Dossier, "related_actor_evidence_status", "observed")
		hit := ActorDefenseRuleHit{
			RuleID: ActorRuleCompoundRelatedActorReuse, Title: "Cross-token related-actor recurrence",
			Tier: "compounding", EvidenceStatus: status, GradeEffect: "compounding_input",
			Count:   track.RelatedActorCount,
			Summary: fmt.Sprintf("%d owner-resolved related wallets recur across the actor token surface.", track.RelatedActorCount),
			Facts:   map[string]any{"related_actor_count": track.RelatedActorCount},
		}
		actorRulePlaceHit(hit, &compound, &watch, &unverified)
	}

	inferredRelations := map[string]int{}
	for _, item := range evidence {
		status := normalizeActorEvidenceStatus(item.VerificationStatus)
		if status == "unverified" {
			unverified++
			continue
		}
		if status == "inferred" {
			inferredRelations[item.Relation]++
			continue
		}

		classification := ClassifyActorDefenseEvidence(item)
		if classification.PossibleDust {
			watch = append(watch, actorRulePossibleDustHit(item, classification))
			continue
		}

		if status == "verified" && track.CreatedTokenCount > 0 && item.Relation == "liquidity_remove_activity" && actorRuleMetadataBool(item.Metadata, "actor_signed") {
			hard = append(hard, actorRuleEvidenceHit(
				ActorRuleHardCreatorLiquidityRemoval,
				"Creator liquidity removal",
				"hard_trigger",
				"verified",
				"D",
				"hard_grade_cap",
				"A parsed liquidity-removal instruction was signed by a wallet already connected to token creation.",
				item,
			))
			continue
		}
		if status == "verified" && track.CreatedTokenCount > 0 &&
			(item.Relation == "direct_sol_transfer_out" || item.Relation == "direct_token_transfer_out") &&
			actorRuleMetadataBool(item.Metadata, "known_related_actor") {
			hard = append(hard, actorRuleEvidenceHit(
				ActorRuleHardCreatorHolderFunding,
				"Direct creator-to-dominant-holder funding",
				"hard_trigger",
				"verified",
				"D",
				"hard_grade_cap",
				"A parsed outgoing transfer connects the creator/deployer wallet to an owner-resolved recurring holder.",
				item,
			))
			continue
		}
		if status == "verified" && actorRulePriorTokenIncident(item) {
			hard = append(hard, actorRuleEvidenceHit(
				ActorRuleHardPriorTokenRug,
				"Verified previous-token removal history",
				"hard_trigger",
				"verified",
				"C",
				"hard_grade_cap",
				"The creator/deployer wallet has transaction-backed rug or liquidity-removal history on a previous token.",
				item,
			))
			continue
		}
		if actorRuleDirectTransfer(item.Relation) {
			actorRuleCollectDirectTransfer(directTransfers, item, status)
		}
		if status == "observed" && item.Relation == "liquidity_remove_activity" {
			compound = append(compound, actorRuleEvidenceHit(
				ActorRuleCompoundObservedRemoval,
				"Observed liquidity-removal activity",
				"compounding",
				"observed",
				"",
				"compounding_input",
				"A parsed instruction or transaction log indicates liquidity-removal activity, but the hard-trigger verification boundary was not met.",
				item,
			))
		}
	}
	compound = append(compound, actorRuleRepeatedTransferHits(directTransfers)...)

	if len(inferredRelations) > 0 {
		relations := make([]string, 0, len(inferredRelations))
		count := 0
		for relation, relationCount := range inferredRelations {
			relations = append(relations, relation)
			count += relationCount
		}
		sort.Strings(relations)
		watch = append(watch, ActorDefenseRuleHit{
			RuleID: ActorRuleWatchInferredEvidence, Title: "Inferred relation watch flag",
			Tier: "watch", EvidenceStatus: "inferred", GradeEffect: "none",
			Count:   count,
			Summary: "Inferred relations remain visible for investigation but cannot lower the grade.",
			Facts:   map[string]any{"relations": relations},
		})
	}

	hard = actorRuleMergeHits(hard)
	compound = actorRuleMergeHits(compound)
	watch = actorRuleMergeHits(watch)
	triggered := append(append([]ActorDefenseRuleHit{}, hard...), compound...)
	actorRuleSortHits(triggered)
	actorRuleSortHits(watch)
	compoundRuleCount := actorRuleDistinctRuleCount(compound)

	grade := "-"
	verdict := "no_grade_trigger"
	decision := []string{
		"VERIFIED hard triggers are evaluated before compounding rules.",
		"ARD-C004 counts distinct transaction signatures for the same relation and counterpart; instruction rows from one signature are deduplicated.",
		"Multiple evidence groups for one rule ID remain separate for audit but count as one compounding rule for grade decisions.",
		"Possible dust/address-poisoning candidates remain visible as watch-only evidence and cannot change the grade.",
		"INFERRED evidence is watch-only and cannot change the grade.",
		"UNVERIFIED evidence is excluded from the verdict.",
	}
	if len(hard) > 0 {
		grade = actorRuleWorstGradeCap(hard)
		verdict = "hard_trigger"
		decision = append(decision, fmt.Sprintf("Hard-trigger ceiling applied: grade %s.", grade))
		if len(compound) > 0 {
			decision = append(decision, "Compounding rules are reported as context and do not move a hard-trigger grade in ruleset v1.0.2.")
		}
	} else if compoundRuleCount >= 2 {
		grade = "B"
		verdict = "compounding_rule"
		decision = append(decision, "Two or more distinct VERIFIED/OBSERVED compounding rule IDs lowered the baseline by one grade to B.")
	} else if compoundRuleCount == 1 {
		verdict = "single_observation"
		decision = append(decision, "One distinct compounding rule ID is insufficient to issue a letter grade, even when it has multiple evidence groups.")
	} else if len(watch) > 0 {
		verdict = "watch_only"
		decision = append(decision, "Only watch flags are present; no letter grade is issued.")
	} else {
		decision = append(decision, "No grade-changing rule was satisfied; absence of evidence is not an A grade.")
	}

	result := ActorDefenseRuleVerdict{
		Grade: grade, Verdict: verdict, RulesetVersion: ActorDefenseRulesetVersion,
		TriggeredRules: triggered, WatchFlags: watch,
		ExcludedUnverifiedEvidence: unverified,
		DecisionPath:               decision,
		NarrativeSource:            "deterministic_rules_only_ai_may_explain_but_not_grade",
		GeneratedAt:                now,
	}
	if grade != "-" && len(triggered) > 0 {
		result.Signed = true
		result.Signature = signActorDefenseRuleVerdict(track, result)
	}
	return result
}

func (s *ActorDefenseStore) PersistRuleVerdict(ctx context.Context, track ActorDefenseTrack, verdict ActorDefenseRuleVerdict) error {
	if s == nil || s.DB == nil {
		return fmt.Errorf("actor defense database is unavailable")
	}
	payload, err := json.Marshal(verdict)
	if err != nil {
		return fmt.Errorf("encode actor rule verdict: %w", err)
	}
	result, err := s.DB.ExecContext(ctx, `
		UPDATE security_threat_tracks
		SET dossier=dossier || jsonb_build_object(
			'rule_verdict',$4::jsonb,
			'ruleset_version',$5,
			'numeric_score_disabled',true
		), updated_at=now()
		WHERE network=$1 AND target_kind=$2 AND target_id=$3`,
		normalizeRadarNetwork(track.Network), firstNonEmptyString(track.TargetKind, "wallet"),
		strings.TrimSpace(track.TargetID), string(payload), verdict.RulesetVersion)
	if err != nil {
		return err
	}
	rows, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rows != 1 {
		return fmt.Errorf("actor defense track was not found for rule verdict persistence")
	}
	return nil
}

func ActorDefenseRuleVerdictFromDossier(dossier map[string]any) (ActorDefenseRuleVerdict, bool) {
	if dossier == nil {
		return ActorDefenseRuleVerdict{}, false
	}
	raw, ok := dossier["rule_verdict"]
	if !ok || raw == nil {
		return ActorDefenseRuleVerdict{}, false
	}
	payload, err := json.Marshal(raw)
	if err != nil {
		return ActorDefenseRuleVerdict{}, false
	}
	var verdict ActorDefenseRuleVerdict
	if err := json.Unmarshal(payload, &verdict); err != nil {
		return ActorDefenseRuleVerdict{}, false
	}
	if strings.TrimSpace(verdict.RulesetVersion) == "" || strings.TrimSpace(verdict.Verdict) == "" {
		return ActorDefenseRuleVerdict{}, false
	}
	return verdict, true
}

func actorRulePlaceHit(hit ActorDefenseRuleHit, compound, watch *[]ActorDefenseRuleHit, unverified *int) {
	switch normalizeActorEvidenceStatus(hit.EvidenceStatus) {
	case "verified", "observed":
		*compound = append(*compound, hit)
	case "inferred":
		hit.Tier = "watch"
		hit.GradeEffect = "none"
		*watch = append(*watch, hit)
	case "unverified":
		(*unverified)++
	}
}

func actorRuleTrackFactStatus(dossier map[string]any, key, fallback string) string {
	if dossier != nil {
		if raw := strings.TrimSpace(fmt.Sprint(dossier[key])); raw != "" && raw != "<nil>" {
			return normalizeActorEvidenceStatus(raw)
		}
	}
	return normalizeActorEvidenceStatus(fallback)
}

func actorRuleEvidenceHit(id, title, tier, status, cap, effect, summary string, item ActorDefenseEvidenceRecord) ActorDefenseRuleHit {
	hit := ActorDefenseRuleHit{
		RuleID: id, Title: title, Tier: tier, EvidenceStatus: status,
		GradeCap: cap, GradeEffect: effect, Count: 1, Summary: summary,
		Facts: map[string]any{
			"relation":         item.Relation,
			"counterpart_kind": item.CounterpartKind,
			"counterpart_id":   item.CounterpartID,
			"observed_at":      item.ObservedAt,
			"occurrence_count": item.OccurrenceCount,
		},
	}
	if strings.TrimSpace(item.EvidenceKey) != "" {
		hit.EvidenceKeys = []string{strings.TrimSpace(item.EvidenceKey)}
	}
	if strings.TrimSpace(item.Signature) != "" {
		hit.Signatures = []string{strings.TrimSpace(item.Signature)}
	}
	return hit
}

func actorRulePossibleDustHit(item ActorDefenseEvidenceRecord, classification ActorDefenseEvidenceClassification) ActorDefenseRuleHit {
	hit := actorRuleEvidenceHit(
		ActorRuleWatchPossibleDust,
		"Possible dust / address-poisoning candidate",
		"watch",
		"inferred",
		"",
		"none",
		classification.Reason,
		item,
	)
	hit.Facts["possible_dust"] = classification.PossibleDust
	hit.Facts["address_poisoning_candidate"] = classification.AddressPoisoningCandidate
	hit.Facts["amount_native"] = item.AmountNative
	hit.Facts["labels"] = classification.Labels
	return hit
}

func actorRuleCollectDirectTransfer(groups map[string]*actorRuleDirectTransferGroup, item ActorDefenseEvidenceRecord, status string) {
	signature := strings.TrimSpace(item.Signature)
	counterpartID := strings.TrimSpace(item.CounterpartID)
	relation := strings.ToLower(strings.TrimSpace(item.Relation))
	if signature == "" || counterpartID == "" || !actorRuleDirectTransfer(relation) {
		return
	}
	counterpartKind := strings.ToLower(strings.TrimSpace(item.CounterpartKind))
	if counterpartKind == "" {
		counterpartKind = "wallet"
	}
	key := strings.Join([]string{relation, counterpartKind, counterpartID}, "|")
	group := groups[key]
	if group == nil {
		group = &actorRuleDirectTransferGroup{
			Relation:        relation,
			CounterpartKind: counterpartKind,
			CounterpartID:   counterpartID,
			EvidenceStatus:  normalizeActorEvidenceStatus(status),
			Signatures:      map[string]bool{},
			EvidenceKeys:    map[string]bool{},
		}
		groups[key] = group
	}
	group.EvidenceStatus = actorRuleConservativeStatus(group.EvidenceStatus, status)
	group.Signatures[signature] = true
	if evidenceKey := strings.TrimSpace(item.EvidenceKey); evidenceKey != "" {
		group.EvidenceKeys[evidenceKey] = true
	}
}

func actorRuleRepeatedTransferHits(groups map[string]*actorRuleDirectTransferGroup) []ActorDefenseRuleHit {
	keys := make([]string, 0, len(groups))
	for key := range groups {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := []ActorDefenseRuleHit{}
	for _, key := range keys {
		group := groups[key]
		signatures := actorRuleMapStrings(group.Signatures)
		if len(signatures) < 2 {
			continue
		}
		out = append(out, ActorDefenseRuleHit{
			RuleID:         ActorRuleCompoundRepeatedTransfer,
			Title:          "Repeated direct transfer relation",
			Tier:           "compounding",
			EvidenceStatus: group.EvidenceStatus,
			GradeEffect:    "compounding_input",
			Count:          len(signatures),
			Summary:        fmt.Sprintf("The %s relation with counterpart %s repeated across %d distinct transaction signatures.", group.Relation, group.CounterpartID, len(signatures)),
			EvidenceKeys:   actorRuleMapStrings(group.EvidenceKeys),
			Signatures:     signatures,
			Facts: map[string]any{
				"relation":                 group.Relation,
				"counterpart_kind":         group.CounterpartKind,
				"counterpart_id":           group.CounterpartID,
				"distinct_signature_count": len(signatures),
				"dedupe_key":               "signature+relation+counterpart",
			},
		})
	}
	return out
}

func actorRuleConservativeStatus(current, candidate string) string {
	current = normalizeActorEvidenceStatus(current)
	candidate = normalizeActorEvidenceStatus(candidate)
	if current == "" || current == "unverified" {
		return candidate
	}
	if candidate == "observed" || candidate == "inferred" || candidate == "unverified" {
		return candidate
	}
	return current
}

func actorRuleMapStrings(items map[string]bool) []string {
	out := make([]string, 0, len(items))
	for item := range items {
		if item = strings.TrimSpace(item); item != "" {
			out = append(out, item)
		}
	}
	sort.Strings(out)
	return out
}

func actorRuleMetadataBool(metadata map[string]any, key string) bool {
	if metadata == nil {
		return false
	}
	value, ok := metadata[key]
	if !ok {
		return false
	}
	switch typed := value.(type) {
	case bool:
		return typed
	case string:
		return strings.EqualFold(strings.TrimSpace(typed), "true")
	default:
		return false
	}
}

func actorRulePriorTokenIncident(item ActorDefenseEvidenceRecord) bool {
	switch strings.ToLower(strings.TrimSpace(item.Relation)) {
	case "prior_token_rug", "prior_token_liquidity_removal", "creator_previous_token_rug", "creator_previous_token_liquidity_removal":
		return true
	default:
		return actorRuleMetadataBool(item.Metadata, "previous_token_incident")
	}
}

func actorRuleDirectTransfer(relation string) bool {
	switch strings.ToLower(strings.TrimSpace(relation)) {
	case "direct_sol_transfer_in", "direct_sol_transfer_out", "direct_token_transfer_in", "direct_token_transfer_out":
		return true
	default:
		return false
	}
}

func actorRuleMergeHits(items []ActorDefenseRuleHit) []ActorDefenseRuleHit {
	merged := map[string]ActorDefenseRuleHit{}
	for _, item := range items {
		key := actorRuleMergeKey(item)
		current, exists := merged[key]
		if !exists {
			item.EvidenceKeys = actorRuleUniqueStrings(item.EvidenceKeys)
			item.Signatures = actorRuleUniqueStrings(item.Signatures)
			actorRuleNormalizeDedupedHit(&item)
			merged[key] = item
			continue
		}
		current.Count += item.Count
		current.EvidenceKeys = actorRuleUniqueStrings(append(current.EvidenceKeys, item.EvidenceKeys...))
		current.Signatures = actorRuleUniqueStrings(append(current.Signatures, item.Signatures...))
		actorRuleNormalizeDedupedHit(&current)
		merged[key] = current
	}
	out := make([]ActorDefenseRuleHit, 0, len(merged))
	for _, item := range merged {
		out = append(out, item)
	}
	actorRuleSortHits(out)
	return out
}

func actorRuleMergeKey(item ActorDefenseRuleHit) string {
	key := item.RuleID + "|" + item.EvidenceStatus + "|" + item.GradeCap
	if item.RuleID == ActorRuleCompoundRepeatedTransfer {
		key += "|" + actorRuleRepeatedTransferIdentity(item)
	}
	return key
}

func actorRuleRepeatedTransferIdentity(hit ActorDefenseRuleHit) string {
	return strings.Join([]string{
		strings.ToLower(actorRuleFactString(hit.Facts, "relation")),
		strings.ToLower(actorRuleFactString(hit.Facts, "counterpart_kind")),
		actorRuleFactString(hit.Facts, "counterpart_id"),
	}, "|")
}

func actorRuleFactString(facts map[string]any, key string) string {
	if facts == nil {
		return ""
	}
	value := strings.TrimSpace(fmt.Sprint(facts[key]))
	if value == "<nil>" {
		return ""
	}
	return value
}

func actorRuleNormalizeDedupedHit(hit *ActorDefenseRuleHit) {
	if hit == nil {
		return
	}
	switch hit.RuleID {
	case ActorRuleCompoundRepeatedTransfer:
		hit.Count = len(actorRuleUniqueStrings(hit.Signatures))
		if hit.Facts == nil {
			hit.Facts = map[string]any{}
		}
		hit.Facts["distinct_signature_count"] = hit.Count
		relation := firstNonEmptyString(actorRuleFactString(hit.Facts, "relation"), "direct_transfer")
		counterpart := firstNonEmptyString(actorRuleFactString(hit.Facts, "counterpart_id"), "unknown_counterpart")
		hit.Summary = fmt.Sprintf("The %s relation with counterpart %s repeated across %d distinct transaction signatures after signature deduplication.", relation, counterpart, hit.Count)
	case ActorRuleWatchPossibleDust:
		if len(hit.Signatures) > 0 {
			hit.Count = len(actorRuleUniqueStrings(hit.Signatures))
		} else if len(hit.EvidenceKeys) > 0 {
			hit.Count = len(actorRuleUniqueStrings(hit.EvidenceKeys))
		}
		hit.Summary = fmt.Sprintf("%d possible dust/address-poisoning candidate observations remain visible but are excluded from grade-changing rules.", hit.Count)
	}
}

func actorRuleDistinctRuleCount(items []ActorDefenseRuleHit) int {
	seen := map[string]bool{}
	for _, item := range items {
		id := strings.TrimSpace(item.RuleID)
		if id == "" {
			continue
		}
		seen[id] = true
	}
	return len(seen)
}

func actorRuleSortHits(items []ActorDefenseRuleHit) {
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Tier != items[j].Tier {
			return items[i].Tier < items[j].Tier
		}
		if items[i].RuleID != items[j].RuleID {
			return items[i].RuleID < items[j].RuleID
		}
		leftIdentity := actorRuleHitSortIdentity(items[i])
		rightIdentity := actorRuleHitSortIdentity(items[j])
		if leftIdentity != rightIdentity {
			return leftIdentity < rightIdentity
		}
		if items[i].EvidenceStatus != items[j].EvidenceStatus {
			return items[i].EvidenceStatus < items[j].EvidenceStatus
		}
		if items[i].Count != items[j].Count {
			return items[i].Count < items[j].Count
		}
		return items[i].Summary < items[j].Summary
	})
}

func actorRuleHitSortIdentity(hit ActorDefenseRuleHit) string {
	if hit.RuleID == ActorRuleCompoundRepeatedTransfer {
		return actorRuleRepeatedTransferIdentity(hit)
	}
	return strings.Join([]string{
		strings.Join(actorRuleUniqueStrings(hit.EvidenceKeys), ","),
		strings.Join(actorRuleUniqueStrings(hit.Signatures), ","),
		strings.TrimSpace(hit.Title),
	}, "|")
}

func actorRuleUniqueStrings(items []string) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, item := range items {
		item = strings.TrimSpace(item)
		if item == "" || seen[item] {
			continue
		}
		seen[item] = true
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func actorRuleWorstGradeCap(hits []ActorDefenseRuleHit) string {
	order := map[string]int{"A": 1, "B": 2, "C": 3, "D": 4, "E": 5, "F": 6}
	grade := "-"
	rank := 0
	for _, hit := range hits {
		candidate := strings.ToUpper(strings.TrimSpace(hit.GradeCap))
		if order[candidate] > rank {
			grade, rank = candidate, order[candidate]
		}
	}
	return grade
}

func signActorDefenseRuleVerdict(track ActorDefenseTrack, verdict ActorDefenseRuleVerdict) string {
	parts := []string{
		verdict.RulesetVersion,
		strings.TrimSpace(track.Network),
		strings.TrimSpace(track.TargetKind),
		strings.TrimSpace(track.TargetID),
		verdict.Grade,
		verdict.Verdict,
	}
	for _, hit := range verdict.TriggeredRules {
		parts = append(parts, strings.Join([]string{
			hit.RuleID,
			hit.EvidenceStatus,
			hit.GradeCap,
			fmt.Sprint(hit.Count),
			strings.Join(actorRuleUniqueStrings(hit.EvidenceKeys), ","),
			strings.Join(actorRuleUniqueStrings(hit.Signatures), ","),
		}, ":"))
	}
	payload := strings.Join(parts, "|")
	hash := sha256.Sum256([]byte(payload))
	return hex.EncodeToString(hash[:])
}
