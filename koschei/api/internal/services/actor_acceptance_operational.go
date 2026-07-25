package services

import (
	"fmt"
	"sort"
	"strings"
)

// EvaluateOperationalActorAcceptance applies the canonical ten-item contract
// and then tightens operational checks whose success depends on collector
// completion metadata. A stored false value is not treated as a completed
// comparison unless the holder source itself was available.
func EvaluateOperationalActorAcceptance(input ActorAcceptanceInput) ActorAcceptanceResult {
	result := EvaluateActorAcceptance(input)
	for index := range result.Items {
		if result.Items[index].ID != "AC-06" {
			continue
		}
		result.Items[index] = operationalRecipientHolderAcceptance(input.Dossier)
	}
	recountOperationalActorAcceptance(&result)
	return result
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
		return actorAcceptanceItemWithLimit(
			"AC-06",
			"Recipients are compared with top-holder evidence",
			ActorAcceptanceNotInvestigated,
			"not_investigated",
			"Recipient-to-top-holder comparison was not investigated.",
			"No mint-specific recipient transfer evidence was available to compare.",
		)
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

func operationalHolderSourceAvailable(status string) bool {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "verified_role_resolution", "dominant_holder_role_unresolved":
		return true
	default:
		return false
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
