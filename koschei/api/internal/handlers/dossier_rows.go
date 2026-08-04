package handlers

import "strings"

func buildDossierSignalRows(report map[string]any) []DossierSignalRow {
	if isActorDossierReport(report) {
		return buildActorDossierSignalRows(report)
	}
	rows := make([]DossierSignalRow, 0, len(signalRegistry))
	for _, def := range signalRegistry {
		state, value := signalStateFor(report, def)
		rows = append(rows, DossierSignalRow{
			ID:          def.ID,
			Label:       def.Label,
			State:       state,
			Value:       value,
			Refs:        dossierRefsForRow(report, def.ID),
			Limitations: signalRowLimitations(state),
		})
	}
	return rows
}

func signalRowLimitations(state string) []string {
	switch state {
	case signalStateNotApplicable:
		return []string{"This check does not apply to this target. Its absence is neither a negative nor a positive finding."}
	case signalStateWindowOpen:
		return []string{"The observation window for this check is still open. A later snapshot may change this row."}
	case signalStatePending:
		return []string{"A Koschei worker owns this check and has not completed it. This is not a customer task."}
	case signalStateNotInvestigated:
		return []string{"This check was not scheduled for this target. No evidence was sought and none is claimed."}
	case signalStateUnavailable:
		return []string{"The source required for this check could not be resolved inside the evidence window."}
	case signalStateUnknown:
		return []string{"The source reported a status Koschei does not recognize. The row is withheld rather than graded."}
	default:
		return nil
	}
}

func dossierRefsForRow(report map[string]any, id string) DossierRefs {
	all := dossierMap(report["evidence_references"])
	value := dossierMap(all[id])
	refs := DossierRefs{
		Wallets: dossierStrings(value["wallets"]), Accounts: dossierStrings(value["accounts"]),
		Signatures: dossierStrings(value["signatures"]), Slots: dossierInt64s(value["slots"]),
		EvidenceKeys: dossierStrings(value["evidence_keys"]),
	}
	// The signed row is an integrity statement rather than an evidence arm. When
	// older snapshots lack a dedicated reference map, attach the immutable
	// verdict signature itself instead of rejecting an otherwise verifiable
	// dossier.
	if id == "signed" && !dossierRefsPresent(refs) {
		signature := strings.TrimSpace(dossierString(dossierMap(report["final_verdict"])["signature"]))
		if signature != "" {
			refs.Signatures = []string{signature}
			refs.EvidenceKeys = []string{"verdict-signature:" + signature}
		}
	}
	return normalizeDossierRefs(refs)
}

func dossierRefsPresent(refs DossierRefs) bool {
	return len(refs.Wallets)+len(refs.Accounts)+len(refs.Signatures)+len(refs.Slots)+len(refs.EvidenceKeys) > 0
}

func normalizeDossierRefs(refs DossierRefs) DossierRefs {
	refs.Wallets = dossierUniqueStrings(refs.Wallets)
	refs.Accounts = dossierUniqueStrings(refs.Accounts)
	refs.Signatures = dossierUniqueStrings(refs.Signatures)
	refs.EvidenceKeys = dossierUniqueStrings(refs.EvidenceKeys)
	refs.Slots = dossierUniqueSlots(refs.Slots)
	return refs
}

func dossierFindModule(report map[string]any, moduleID string) map[string]any {
	module, _ := resolveSignalSource(report, signalSource{Kind: signalSourceModule, Key: strings.TrimSpace(moduleID)})
	return module
}

func dossierFindBehavior(report map[string]any, ruleID string) map[string]any {
	signal, _ := resolveSignalSource(report, signalSource{Kind: signalSourceBehavior, Key: strings.TrimSpace(ruleID)})
	return signal
}
