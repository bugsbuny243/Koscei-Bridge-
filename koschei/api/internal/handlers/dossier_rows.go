package handlers

import "strings"

func buildDossierSignalRows(report map[string]any) []DossierSignalRow {
	if isActorDossierReport(report) {
		return buildActorDossierSignalRows(report)
	}
	launch := report["launch_forensics"]
	holder := report["holder_intelligence"]
	market := report["market"]
	lp := report["lp_control"]
	actor := report["actor_investigation"]
	final := report["final_verdict"]
	ledger := report["trade_ledger_aggregates"]
	behaviorC003 := dossierFindBehavior(report, "URD-C003")
	behaviorC004 := dossierFindBehavior(report, "URD-C004")
	behaviorC005 := dossierFindBehavior(report, "URD-C005")
	authority := dossierFindModule(report, "authority")

	funding := dossierFindModule(report, "funding")
	liquidityMovement := dossierFindModule(report, "liquidity_movement")
	program := dossierFindModule(report, "program")
	metadata := dossierFindModule(report, "metadata")
	claim := dossierFindModule(report, "claim")
	mev := dossierFindModule(report, "mev")

	return []DossierSignalRow{
		dossierSignalRow(report, "launch", "Launch time / age", launch, dossierObservedState(launch, "arm_pending")),
		dossierSignalRow(report, "mint", "Mint authority", authority, dossierEvidenceState(authority, "arm_pending")),
		dossierSignalRow(report, "freeze", "Freeze authority", authority, dossierEvidenceState(authority, "arm_pending")),
		dossierSignalRow(report, "wash", "Wash-trading context", ledger, dossierObservedState(ledger, "window_open")),
		dossierSignalRow(report, "address", "Address behavior", actor, dossierObservedState(actor, "arm_pending")),
		dossierSignalRow(report, "liquidity", "Liquidity amount + control", dossierFirst(lp, market), dossierLiquidityState(lp, market)),
		dossierSignalRow(report, "funding", "Creator funding origin", funding, dossierEvidenceState(funding, "arm_pending")),
		dossierSignalRow(report, "concentration", "Owner-resolved holder concentration", dossierFirst(behaviorC005, holder), dossierConcentrationState(behaviorC005, holder)),
		dossierSignalRow(report, "sniper", "Sniper timing", launch, dossierObservedState(launch, "window_open")),
		dossierSignalRow(report, "first-buyer", "First-buyer linkage", launch, dossierObservedState(launch, "window_open")),
		dossierSignalRow(report, "track", "Creator track record", actor, dossierObservedState(actor, "arm_pending")),
		dossierSignalRow(report, "creator-sell", "Creator sell behavior", behaviorC003, dossierEvidenceState(behaviorC003, "window_open")),
		dossierSignalRow(report, "dominant-exit", "Dominant-holder exit", behaviorC004, dossierEvidenceState(behaviorC004, "window_open")),
		dossierSignalRow(report, "liq-move", "Liquidity movement", liquidityMovement, dossierEvidenceState(liquidityMovement, "arm_pending")),
		dossierSignalRow(report, "program", "Program relations", program, dossierEvidenceState(program, "arm_pending")),
		dossierSignalRow(report, "metadata", "Metadata / impersonation", metadata, dossierEvidenceState(metadata, "arm_pending")),
		dossierSignalRow(report, "claim", "Claim / airdrop surface", claim, dossierEvidenceState(claim, "not_applicable")),
		dossierSignalRow(report, "mev", "MEV exposure", mev, dossierEvidenceState(mev, "not_applicable")),
		dossierSignalRow(report, "distribution", "Launch distribution", launch, dossierObservedState(launch, "window_open")),
		dossierSignalRow(report, "signed", "Signed final verdict", final, dossierSignedState(final)),
	}
}

func dossierSignalRow(report map[string]any, id, label string, value any, state string) DossierSignalRow {
	return DossierSignalRow{ID: id, Label: label, State: state, Value: value, Refs: dossierRefsForRow(report, id)}
}

func dossierRefsForRow(report map[string]any, id string) DossierRefs {
	all := dossierMap(report["evidence_references"])
	value := dossierMap(all[id])
	return normalizeDossierRefs(DossierRefs{
		Wallets: dossierStrings(value["wallets"]), Accounts: dossierStrings(value["accounts"]),
		Signatures: dossierStrings(value["signatures"]), Slots: dossierInt64s(value["slots"]),
		EvidenceKeys: dossierStrings(value["evidence_keys"]),
	})
}

func dossierObservedState(value any, fallback string) string {
	m := dossierMap(value)
	if len(m) == 0 { return fallback }
	status := strings.ToLower(dossierString(m["status"]))
	if status == "not_applicable" { return "not_applicable" }
	if status == "source_unavailable" { return "arm_pending" }
	return "observed"
}

func dossierEvidenceState(value any, fallback string) string {
	m := dossierMap(value)
	if len(m) == 0 { return fallback }
	status := strings.ToLower(firstNonEmptyString(
		dossierString(m["evidence_status"]), dossierString(m["verification_status"]),
		dossierString(m["execution_status"]), dossierString(m["status"]),
	))
	switch status {
	case "verified":
		return "verified"
	case "observed", "completed", "observed_market_snapshot", "verified_market_snapshot":
		return "observed"
	case "not_applicable":
		return "not_applicable"
	case "source_unavailable", "evidence_pending", "insufficient_evidence", "unverified":
		return "arm_pending"
	}
	if dossierBool(m["signed"]) || dossierBool(m["verified"]) { return "verified" }
	return "observed"
}

func dossierLiquidityState(lp, market any) string {
	status := strings.ToLower(dossierString(dossierMap(lp)["status"]))
	switch status {
	case "burned", "locked_until":
		return "verified"
	case "held_by_creator", "unverified":
		return "observed"
	case "not_applicable":
		return "not_applicable"
	case "source_unavailable":
		return "arm_pending"
	}
	return dossierObservedState(market, "arm_pending")
}

func dossierConcentrationState(signal, holder any) string {
	if state := dossierEvidenceState(signal, ""); state == "verified" || state == "observed" { return state }
	return dossierObservedState(holder, "arm_pending")
}

func dossierSignedState(value any) string {
	m := dossierMap(value)
	if dossierBool(m["signed"]) && strings.TrimSpace(dossierString(m["signature"])) != "" { return "verified" }
	return "arm_pending"
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

func dossierFindModule(report map[string]any, needle string) map[string]any {
	needle = strings.ToLower(strings.TrimSpace(needle))
	for _, item := range dossierSlice(dossierFirst(report["evidence_arms"], report["modules"])) {
		module := dossierMap(item)
		id := strings.ToLower(firstNonEmptyString(dossierString(module["module_id"]), dossierString(module["module"])))
		if strings.Contains(id, needle) { return module }
	}
	return map[string]any{}
}

func dossierFindBehavior(report map[string]any, ruleID string) map[string]any {
	behavior := dossierMap(report["behavior_signals"])
	for _, item := range dossierSlice(behavior["signals"]) {
		signal := dossierMap(item)
		if dossierString(signal["rule_id"]) == ruleID { return signal }
	}
	return map[string]any{}
}
