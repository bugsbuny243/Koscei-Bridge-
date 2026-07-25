package handlers

import (
	"fmt"
	"strings"
)

const dossierActorMapperVersion = "koschei-actor-acceptance-v1+evidence-log-v1"

func isActorDossierReport(report map[string]any) bool {
	return strings.EqualFold(strings.TrimSpace(dossierString(report["analysis_scope"])), "wallet_actor_investigation")
}

func buildActorDossierSignalRows(report map[string]any) []DossierSignalRow {
	acceptance := dossierMap(report["actor_acceptance"])
	items := dossierSlice(acceptance["items"])
	rows := make([]DossierSignalRow, 0, len(items))
	for _, raw := range items {
		item := dossierMap(raw)
		id := strings.TrimSpace(dossierString(item["id"]))
		if id == "" {
			continue
		}
		evidence := dossierSlice(item["evidence"])
		rows = append(rows, DossierSignalRow{
			ID:               id,
			Label:            strings.TrimSpace(dossierString(item["question"])),
			State:            normalizeActorDossierState(dossierString(item["evidence_state"])),
			AcceptanceStatus: strings.ToLower(strings.TrimSpace(dossierString(item["status"]))),
			Value: map[string]any{
				"summary":  item["summary"],
				"evidence": evidence,
			},
			Refs:        actorDossierRefs(evidence),
			Limitations: dossierStrings(item["limitations"]),
		})
	}
	return rows
}

func normalizeActorDossierState(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "verified":
		return "verified"
	case "observed", "verified_or_observed":
		return "observed"
	case "inferred":
		return "inferred"
	case "not_verified":
		return "not_verified"
	case "not_investigated":
		return "not_investigated"
	case "unavailable", "unverified":
		return "unavailable"
	default:
		return "unavailable"
	}
}

func actorDossierRefs(evidence []any) DossierRefs {
	refs := DossierRefs{}
	for _, raw := range evidence {
		row := dossierMap(raw)
		refs.Wallets = append(refs.Wallets,
			strings.TrimSpace(dossierString(row["source_wallet"])),
			strings.TrimSpace(dossierString(row["destination_wallet"])),
		)
		refs.Signatures = append(refs.Signatures, strings.TrimSpace(dossierString(row["signature"])))
		if slot := dossierInt64(row["slot"]); slot > 0 {
			refs.Slots = append(refs.Slots, slot)
		}
		refs.EvidenceKeys = append(refs.EvidenceKeys, strings.TrimSpace(dossierString(row["evidence_key"])))
	}
	return normalizeDossierRefs(refs)
}

func actorDossierTarget(snapshot dossierSnapshot) map[string]any {
	wallet := strings.TrimSpace(dossierString(snapshot.Report["wallet"]))
	if wallet == "" {
		wallet = strings.TrimSpace(snapshot.Mint)
	}
	return map[string]any{
		"kind":             "wallet",
		"id":               wallet,
		"network":          snapshot.Network,
		"requested_target": strings.TrimSpace(dossierString(snapshot.Report["target"])),
		"identity_scope":   "onchain_wallet_only",
	}
}

func actorDossierCreatedTokens(report map[string]any) any {
	actor := dossierMap(report["actor_investigation"])
	dossier := dossierMap(actor["dossier"])
	createdItem := actorDossierAcceptanceItem(report, "AC-03")
	creationEvidence := dossierSlice(createdItem["evidence"])
	rows := []any{}
	for _, raw := range dossierSlice(dossier["tokens"]) {
		token := dossierMap(raw)
		if !actorDossierHasRole(token["roles"], "creator_deployer") {
			continue
		}
		mint := strings.TrimSpace(dossierString(token["mint"]))
		matched := []any{}
		state := "unverified"
		for _, evidenceRaw := range creationEvidence {
			evidence := dossierMap(evidenceRaw)
			if mint == "" {
				continue
			}
			if strings.EqualFold(mint, dossierString(evidence["token_mint"])) || strings.EqualFold(mint, dossierString(evidence["destination_wallet"])) {
				matched = append(matched, evidence)
				state = normalizeActorDossierState(dossierString(evidence["verification_status"]))
			}
		}
		limitations := []string{}
		if len(matched) == 0 {
			limitations = append(limitations, "Creator-role observation exists, but a complete creator-to-mint evidence line is unavailable in this bundle.")
		}
		rows = append(rows, map[string]any{
			"mint":                mint,
			"name":                token["name"],
			"symbol":              token["symbol"],
			"roles":               token["roles"],
			"creation_signature":  token["creator_signature"],
			"first_observed_at":   token["first_observed_at"],
			"last_observed_at":    token["last_observed_at"],
			"verification_status": state,
			"evidence":            matched,
			"limitations":         limitations,
		})
	}
	return rows
}

func actorDossierFundingOrigin(report map[string]any) any {
	actor := dossierMap(report["actor_investigation"])
	return dossierFirst(actor["funding_origin"], map[string]any{
		"status": "not_investigated", "verification_status": "unverified",
	})
}

func actorDossierConnections(report map[string]any) map[string]any {
	actor := dossierMap(report["actor_investigation"])
	dossier := dossierMap(actor["dossier"])
	track := dossierMap(dossier["track"])
	acceptance := actorDossierAcceptanceItem(report, "AC-08")
	related := []any{}
	for _, raw := range dossierSlice(dossier["related_actors"]) {
		item := dossierMap(raw)
		related = append(related, map[string]any{
			"wallet": item["wallet"],
			"shared_token_count": item["shared_token_count"],
			"max_holder_percentage": item["max_holder_percentage"],
			"first_observed_at": item["first_observed_at"],
			"last_observed_at": item["last_observed_at"],
			"verification_status": "observed",
			"source": "persistent_actor_index",
			"limitation": "Observed recurrence is not identity, intent or common-control proof.",
		})
	}
	return map[string]any{
		"acceptance_status": acceptance["status"],
		"evidence_state": acceptance["evidence_state"],
		"summary": acceptance["summary"],
		"evidence": dossierFirst(acceptance["evidence"], []any{}),
		"limitations": dossierStrings(acceptance["limitations"]),
		"related_actor_observations": related,
		"evidence_graph": dossierFirst(actor["evidence_graph"], map[string]any{}),
		"counts": map[string]any{
			"verification_status": "observed",
			"created_tokens": track["created_token_count"],
			"dominant_holder_tokens": track["dominant_holder_token_count"],
			"related_actors": track["related_actor_count"],
		},
		"boundary": "Observed recurrence does not prove identity, intent or common control.",
	}
}

func actorDossierEvidenceLog(report map[string]any) any {
	actor := dossierMap(report["actor_investigation"])
	dossier := dossierMap(actor["dossier"])
	return dossierFirst(dossier["evidence"], []any{})
}

func actorDossierSectionLimitations(report map[string]any) map[string]any {
	acceptance := dossierMap(report["actor_acceptance"])
	byItem := map[string]any{}
	for _, raw := range dossierSlice(acceptance["items"]) {
		item := dossierMap(raw)
		id := strings.TrimSpace(dossierString(item["id"]))
		limitations := dossierStrings(item["limitations"])
		if id != "" && len(limitations) > 0 {
			byItem[id] = limitations
		}
	}
	actor := dossierMap(report["actor_investigation"])
	funding := dossierMap(actor["funding_origin"])
	live := dossierMap(actor["actor_live_evidence"])
	if len(live) == 0 {
		live = dossierMap(actor["live_evidence"])
	}
	return map[string]any{
		"acceptance_items": byItem,
		"funding_origin": dossierStrings(funding["limitations"]),
		"live_evidence": dossierStrings(live["limitations"]),
		"created_token_history": []string{
			"Created-token observations require exact creator-to-mint evidence before they are presented as verified relations.",
		},
		"cross_token_connections": []string{
			"Cross-token recurrence is relationship evidence only; it is not a real-world identity or intent claim.",
		},
		"evidence_log": []string{
			"Collection remains bounded by persisted source windows and mint-specific ATA policy; missing rows are not treated as absence of activity.",
		},
	}
}

func actorDossierAcceptanceItem(report map[string]any, id string) map[string]any {
	acceptance := dossierMap(report["actor_acceptance"])
	for _, raw := range dossierSlice(acceptance["items"]) {
		item := dossierMap(raw)
		if strings.EqualFold(strings.TrimSpace(dossierString(item["id"])), strings.TrimSpace(id)) {
			return item
		}
	}
	return map[string]any{}
}

func actorDossierHasRole(value any, role string) bool {
	for _, candidate := range dossierStrings(value) {
		if strings.EqualFold(candidate, strings.TrimSpace(role)) {
			return true
		}
	}
	return false
}

func validateActorDossierRows(rows []DossierSignalRow) error {
	if len(rows) != 10 {
		return fmt.Errorf("actor acceptance requires 10 ordered items, got %d", len(rows))
	}
	for index, row := range rows {
		expected := fmt.Sprintf("AC-%02d", index+1)
		if row.ID != expected {
			return fmt.Errorf("actor acceptance item order mismatch: expected %s, got %s", expected, row.ID)
		}
		switch row.AcceptanceStatus {
		case "pass", "fail", "not_investigated":
		default:
			return fmt.Errorf("actor acceptance item %s has invalid status %q", row.ID, row.AcceptanceStatus)
		}
		if (row.State == "verified" || row.State == "observed") && !dossierRefsPresent(row.Refs) {
			return fmt.Errorf("%w: %s", errDossierReferenceMissing, row.ID)
		}
	}
	return nil
}
