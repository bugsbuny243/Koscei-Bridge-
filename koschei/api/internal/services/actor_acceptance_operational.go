package services

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// EvaluateOperationalActorAcceptance applies the canonical ten-item contract
// and then separates three different outcomes:
//   - a completed check with a positive or negative result: pass;
//   - a collector that ran but could not complete its evidence contract: fail;
//   - a collector that did not run: not_investigated.
//
// Absence of a risky finding is not a collector failure. A signed,
// evidence-bounded WITHHOLD is a valid deterministic verdict, not a letter
// grade or safety label.
func EvaluateOperationalActorAcceptance(input ActorAcceptanceInput) ActorAcceptanceResult {
	result := EvaluateActorAcceptance(input)
	for index := range result.Items {
		switch result.Items[index].ID {
		case "AC-05":
			result.Items[index] = operationalRecipientAcceptance(input.Dossier)
		case "AC-06":
			result.Items[index] = operationalRecipientHolderAcceptance(input.Dossier)
		case "AC-07":
			result.Items[index] = operationalLiquidityAcceptance(input.Dossier)
		case "AC-08":
			result.Items[index] = operationalCrossTokenAcceptance(input.Dossier)
		case "AC-10":
			result.Items[index] = operationalActorVerdictAcceptance(input.Verdict)
		}
	}
	recountOperationalActorAcceptance(&result)
	return result
}

func operationalRecipientAcceptance(dossier ActorDefenseDossier) ActorAcceptanceItem {
	base := actorAcceptanceRecipients(dossier)
	if base.Status == ActorAcceptancePass {
		return base
	}
	coverage := actorAcceptanceCoverageMap(dossier.Coverage["acceptance_distribution"])
	status := actorAcceptanceCoverageString(coverage, "status")
	switch status {
	case "complete":
		return actorAcceptanceItem(
			"AC-05",
			"Creator token exits and recipient wallets are resolved",
			ActorAcceptancePass,
			"not_observed",
			"The bounded mint-specific ATA investigation completed and no qualifying creator distribution recipient was observed in the accepted window.",
			[]ActorAcceptanceEvidenceLine{},
		)
	case "no_creator_mints":
		return actorAcceptanceItem(
			"AC-05",
			"Creator token exits and recipient wallets are resolved",
			ActorAcceptancePass,
			"not_applicable",
			"No creator_deployer mint was available, so there was no creator distribution surface to investigate.",
			[]ActorAcceptanceEvidenceLine{},
		)
	case "", "not_investigated", "stored_evidence_only", "rpc_unavailable", "database_unavailable":
		return base
	default:
		return actorAcceptanceItemWithLimit(
			"AC-05",
			"Creator token exits and recipient wallets are resolved",
			ActorAcceptanceFail,
			"unavailable",
			"The mint-specific recipient worker ran but did not complete the accepted creator-distribution coverage.",
			actorAcceptanceCoverageLimitation(coverage, "Distribution worker status: "+status+"."),
		)
	}
}

func operationalActorVerdictAcceptance(verdict ActorDefenseRuleVerdict) ActorAcceptanceItem {
	view := actorAcceptanceVerdict(verdict)
	if view.Grade != "-" {
		return actorAcceptanceVerdictItem(view)
	}
	allowed := map[string]bool{
		"single_observation": true,
		"watch_only":         true,
		"no_grade_trigger":   true,
	}
	if view.Signed && strings.TrimSpace(view.Signature) != "" &&
		strings.TrimSpace(view.RulesetVersion) != "" &&
		allowed[strings.TrimSpace(view.Verdict)] && len(view.DecisionPath) > 0 {
		return actorAcceptanceItem(
			"AC-10",
			"One evidence-backed deterministic verdict is produced",
			ActorAcceptancePass,
			"withheld",
			"Deterministic verdict: WITHHOLD — available evidence does not justify a letter grade; absence of evidence is not an A grade.",
			[]ActorAcceptanceEvidenceLine{{
				Kind: "control", EvidenceKey: "actor-withhold:" + view.Signature,
				Relation: "deterministic_withhold_verdict", SourceWallet: "koschei-rules",
				DestinationWallet: "actor-case", Amount: "not_applicable",
				Program: "koschei-actor-defense-rules", VerificationStatus: "withheld",
				EvidenceSource: view.RulesetVersion,
			}},
		)
	}
	return actorAcceptanceItemWithLimit(
		"AC-10",
		"One evidence-backed deterministic verdict is produced",
		ActorAcceptanceFail,
		"not_verified",
		"Neither an evidence-backed letter grade nor a signed deterministic WITHHOLD satisfies the actor ruleset contract.",
		"WITHHOLD requires a target-bound signature, ruleset version, explicit verdict state and deterministic decision path.",
	)
}

func operationalRecipientHolderAcceptance(dossier ActorDefenseDossier) ActorAcceptanceItem {
	rows := []ActorAcceptanceEvidenceLine{}
	statuses := map[string]bool{}
	recipientEvidence := 0
	complete := true
	matched := 0

	for _, item := range dossier.Evidence {
		if !actorAcceptanceRelationIn(item.Relation, "initial_token_recipient", "creator_recipient_in_window") {
			continue
		}
		recipientEvidence++
		status := strings.ToLower(strings.TrimSpace(actorAcceptanceMetadataString(item.Metadata, "top_holder_status")))
		if status == "" {
			status = "missing"
		}
		statuses[status] = true
		if !operationalHolderSourceAvailable(status) {
			complete = false
			continue
		}
		row, ok := actorAcceptanceChainLine(item)
		if !ok {
			complete = false
			continue
		}
		rows = append(rows, row)
		if actorAcceptanceMetadataBool(item.Metadata, "matches_top_holder") {
			matched++
		}
	}

	if recipientEvidence == 0 {
		coverage := actorAcceptanceCoverageMap(dossier.Coverage["acceptance_distribution"])
		status := actorAcceptanceCoverageString(coverage, "status")
		switch status {
		case "complete":
			return actorAcceptanceItem(
				"AC-06",
				"Recipients are compared with top-holder evidence",
				ActorAcceptancePass,
				"not_applicable",
				"The distribution worker completed without a qualifying recipient set, so there was no recipient to compare with top holders.",
				[]ActorAcceptanceEvidenceLine{},
			)
		case "no_creator_mints":
			return actorAcceptanceItem(
				"AC-06",
				"Recipients are compared with top-holder evidence",
				ActorAcceptancePass,
				"not_applicable",
				"No creator mint or recipient set was available for top-holder comparison.",
				[]ActorAcceptanceEvidenceLine{},
			)
		default:
			return actorAcceptanceItemWithLimit(
				"AC-06",
				"Recipients are compared with top-holder evidence",
				ActorAcceptanceNotInvestigated,
				"not_investigated",
				"Recipient-to-top-holder comparison was not investigated.",
				actorAcceptanceCoverageLimitation(coverage, "No completed mint-specific recipient set was available to compare."),
			)
		}
	}
	if complete && len(rows) == recipientEvidence {
		actorAcceptanceSortEvidence(rows)
		return actorAcceptanceItem(
			"AC-06",
			"Recipients are compared with top-holder evidence",
			ActorAcceptancePass,
			"verified",
			fmt.Sprintf("Top-holder comparison completed for %d recipient evidence line(s); %d recipient(s) matched the current top-holder snapshot.", recipientEvidence, matched),
			rows,
		)
	}

	statusList := make([]string, 0, len(statuses))
	for status := range statuses {
		statusList = append(statusList, status)
	}
	sort.Strings(statusList)
	return actorAcceptanceItemWithLimit(
		"AC-06",
		"Recipients are compared with top-holder evidence",
		ActorAcceptanceFail,
		"not_verified",
		"Recipient evidence exists, but top-holder comparison did not complete against an available holder source.",
		"Holder source status: "+strings.Join(statusList, ", ")+". A false match is valid only after supply, largest accounts and owner-wallet resolution completed.",
	)
}

func operationalLiquidityAcceptance(dossier ActorDefenseDossier) ActorAcceptanceItem {
	base := actorAcceptanceLiquidity(dossier)
	if base.Status == ActorAcceptancePass {
		return base
	}
	coverage := actorAcceptanceCoverageMap(dossier.Coverage["acceptance_liquidity"])
	status := actorAcceptanceCoverageString(coverage, "status")
	switch status {
	case "complete_no_explicit_liquidity_observed":
		return actorAcceptanceItem(
			"AC-07",
			"Liquidity add or remove activity is shown with signatures",
			ActorAcceptancePass,
			"not_observed",
			"The bounded creator-wallet liquidity worker completed and found no explicit parsed add/increase or remove/decrease instruction with a pool, program and creator-linked mint.",
			[]ActorAcceptanceEvidenceLine{},
		)
	case "no_creator_mints":
		return actorAcceptanceItem(
			"AC-07",
			"Liquidity add or remove activity is shown with signatures",
			ActorAcceptancePass,
			"not_applicable",
			"No creator-linked mint was available for liquidity investigation.",
			[]ActorAcceptanceEvidenceLine{},
		)
	case "", "not_investigated", "stored_evidence_only", "rpc_unavailable", "database_unavailable":
		return base
	case "complete_with_evidence":
		return actorAcceptanceItemWithLimit(
			"AC-07",
			"Liquidity add or remove activity is shown with signatures",
			ActorAcceptanceFail,
			"not_verified",
			"The liquidity worker reported explicit evidence, but no complete canonical row was visible in the refreshed dossier.",
			"Liquidity evidence persistence or dossier refresh did not complete.",
		)
	default:
		return actorAcceptanceItemWithLimit(
			"AC-07",
			"Liquidity add or remove activity is shown with signatures",
			ActorAcceptanceFail,
			"unavailable",
			"The bounded liquidity worker ran but did not complete its explicit pool/program evidence contract.",
			actorAcceptanceCoverageLimitation(coverage, "Liquidity worker status: "+status+"."),
		)
	}
}

func operationalCrossTokenAcceptance(dossier ActorDefenseDossier) ActorAcceptanceItem {
	base := actorAcceptanceRepeatActors(dossier)
	if base.Status == ActorAcceptancePass {
		return base
	}

	groups := map[string]map[string]bool{}
	rowsByWallet := map[string][]ActorAcceptanceEvidenceLine{}
	for _, item := range dossier.Evidence {
		if !actorAcceptanceRelationIn(item.Relation, "initial_token_recipient", "creator_recipient_in_window") ||
			!actorAcceptanceMetadataBool(item.Metadata, "matches_top_holder") ||
			!operationalHolderSourceAvailable(actorAcceptanceMetadataString(item.Metadata, "top_holder_status")) {
			continue
		}
		wallet := strings.TrimSpace(item.CounterpartID)
		mint := strings.TrimSpace(item.TokenMint)
		row, ok := actorAcceptanceChainLine(item)
		if wallet == "" || mint == "" || !ok {
			continue
		}
		if groups[wallet] == nil {
			groups[wallet] = map[string]bool{}
		}
		groups[wallet][mint] = true
		rowsByWallet[wallet] = append(rowsByWallet[wallet], row)
	}
	for wallet, mints := range groups {
		if len(mints) < 2 {
			continue
		}
		rows := rowsByWallet[wallet]
		actorAcceptanceSortEvidence(rows)
		return actorAcceptanceItem(
			"AC-08",
			"Creator and dominant-holder recurrence is found across tokens",
			ActorAcceptancePass,
			"observed",
			fmt.Sprintf("Owner-resolved recipient %s matched the top-holder snapshot across %d creator mint(s). This is relationship evidence, not identity or common-control proof.", wallet, len(mints)),
			rows,
		)
	}

	coverage := actorAcceptanceCoverageMap(dossier.Coverage["acceptance_distribution"])
	status := actorAcceptanceCoverageString(coverage, "status")
	discovered := actorAcceptanceCoverageInt(coverage, "mints_discovered")
	completed := actorAcceptanceCoverageInt(coverage, "mints_completed")
	recipients := actorAcceptanceCoverageInt(coverage, "recipients_resolved")
	comparisons := actorAcceptanceCoverageInt(coverage, "holder_comparisons")

	// Never infer not_applicable from zero-valued counters when the worker did not
	// run. Completion status is the authority for coverage semantics.
	if status == "" || status == "not_investigated" || status == "stored_evidence_only" || status == "rpc_unavailable" || status == "database_unavailable" {
		return actorAcceptanceItemWithLimit(
			"AC-08",
			"Creator and dominant-holder recurrence is found across tokens",
			ActorAcceptanceNotInvestigated,
			"not_investigated",
			"Cross-token creator and holder recurrence was not investigated.",
			actorAcceptanceCoverageLimitation(coverage, "Distribution and holder comparison coverage was not available."),
		)
	}
	if status == "no_creator_mints" || (status == "complete" && discovered < 2) {
		return actorAcceptanceItem(
			"AC-08",
			"Creator and dominant-holder recurrence is found across tokens",
			ActorAcceptancePass,
			"not_applicable",
			"Fewer than two creator mints were available, so no cross-token creator/holder recurrence surface existed.",
			[]ActorAcceptanceEvidenceLine{},
		)
	}
	if status == "complete" && completed >= 2 && comparisons == recipients {
		return actorAcceptanceItem(
			"AC-08",
			"Creator and dominant-holder recurrence is found across tokens",
			ActorAcceptancePass,
			"not_observed",
			fmt.Sprintf("Cross-token comparison completed across %d creator mint(s); no owner-resolved recipient was a top holder across two or more creator mints.", completed),
			[]ActorAcceptanceEvidenceLine{},
		)
	}
	return actorAcceptanceItemWithLimit(
		"AC-08",
		"Creator and dominant-holder recurrence is found across tokens",
		ActorAcceptanceFail,
		"not_verified",
		"Cross-token comparison started but did not complete across the creator mint and holder surface.",
		actorAcceptanceCoverageLimitation(coverage, fmt.Sprintf("Distribution status=%s; mints completed=%d/%d; holder comparisons=%d/%d recipients.", status, completed, discovered, comparisons, recipients)),
	)
}

func operationalHolderSourceAvailable(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "verified_role_resolution", "dominant_holder_role_unresolved":
		return true
	default:
		return false
	}
}

func actorAcceptanceCoverageMap(value any) map[string]any {
	if value == nil {
		return map[string]any{}
	}
	if mapped, ok := value.(map[string]any); ok {
		return mapped
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return map[string]any{}
	}
	mapped := map[string]any{}
	if json.Unmarshal(encoded, &mapped) != nil {
		return map[string]any{}
	}
	return mapped
}

func actorAcceptanceCoverageString(coverage map[string]any, key string) string {
	return strings.ToLower(strings.TrimSpace(publicCaseAnyStringForAcceptance(coverage[key])))
}

func actorAcceptanceCoverageInt(coverage map[string]any, key string) int {
	return publicCaseIntForAcceptance(coverage[key])
}

func actorAcceptanceCoverageLimitation(coverage map[string]any, fallback string) string {
	for _, raw := range actorAcceptanceSliceForCoverage(coverage["limitations"]) {
		value := strings.TrimSpace(publicCaseAnyStringForAcceptance(raw))
		if value != "" {
			return value
		}
	}
	return fallback
}

func actorAcceptanceSliceForCoverage(value any) []any {
	if value == nil {
		return nil
	}
	if rows, ok := value.([]any); ok {
		return rows
	}
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil
	}
	rows := []any{}
	if json.Unmarshal(encoded, &rows) != nil {
		return nil
	}
	return rows
}

func publicCaseAnyStringForAcceptance(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return fmt.Sprintf("%v", typed)
	case float32:
		return fmt.Sprintf("%v", typed)
	case int:
		return fmt.Sprint(typed)
	case int64:
		return fmt.Sprint(typed)
	case nil:
		return ""
	default:
		return fmt.Sprint(typed)
	}
}

func publicCaseIntForAcceptance(value any) int {
	switch typed := value.(type) {
	case int:
		return typed
	case int64:
		return int(typed)
	case float64:
		return int(typed)
	case float32:
		return int(typed)
	case json.Number:
		parsed, _ := typed.Int64()
		return int(parsed)
	default:
		var parsed int
		fmt.Sscan(strings.TrimSpace(publicCaseAnyStringForAcceptance(value)), &parsed)
		return parsed
	}
}

func recountOperationalActorAcceptance(result *ActorAcceptanceResult) {
	if result == nil {
		return
	}
	result.PassCount = 0
	result.FailCount = 0
	result.NotInvestigatedCount = 0
	for _, item := range result.Items {
		switch item.Status {
		case ActorAcceptancePass:
			result.PassCount++
		case ActorAcceptanceFail:
			result.FailCount++
		default:
			result.NotInvestigatedCount++
		}
	}
	switch {
	case result.FailCount > 0:
		result.Status = ActorAcceptanceFail
	case result.NotInvestigatedCount > 0:
		result.Status = "partial"
	default:
		result.Status = ActorAcceptancePass
	}
	result.AcceptanceHash = actorAcceptanceHash(*result)
}
