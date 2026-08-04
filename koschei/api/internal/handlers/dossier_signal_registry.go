package handlers

import "strings"

// Signal registry.
//
// The customer card is declared once here. Every detector owns one stable row,
// one exact source and one canonical evidence state. Adding a detector without
// registering its customer-facing row is therefore a test failure rather than
// a silent product gap.
const (
	signalStateVerified        = "verified"
	signalStateObserved        = "observed"
	signalStateInferred        = "inferred"
	signalStateNotApplicable   = "not_applicable"
	signalStateWindowOpen      = "window_open"
	signalStatePending         = "pending"
	signalStateNotInvestigated = "not_investigated"
	signalStateUnavailable     = "unavailable"
	signalStateUnknown         = "unknown"
)

const (
	signalGroupEvidence = "evidence"
	signalGroupInferred = "inferred"
	signalGroupOpen     = "open"
	signalGroupClosed   = "closed"
	signalGroupBlocked  = "blocked"
)

const (
	signalSourceModule   = "module"
	signalSourceBehavior = "behavior"
	signalSourceReport   = "report"
)

type signalSource struct {
	Kind string
	Key  string
	// Field is a dotted path inside the source. It lets rows share an arm while
	// reading different facts, for example signals.mint_authority_present and
	// signals.freeze_authority_present.
	Field string
}

type signalDefinition struct {
	ID          string
	Label       string
	Source      signalSource
	RequireRefs bool
}

var signalRegistry = []signalDefinition{
	{ID: "launch", Label: "Launch time / age", Source: signalSource{signalSourceReport, "launch_forensics", "launch_slot"}, RequireRefs: true},
	{ID: "mint", Label: "Mint authority", Source: signalSource{signalSourceModule, "token_authority_scanner", "signals.mint_authority_present"}, RequireRefs: true},
	{ID: "freeze", Label: "Freeze authority", Source: signalSource{signalSourceModule, "token_authority_scanner", "signals.freeze_authority_present"}, RequireRefs: true},
	{ID: "update-authority", Label: "Update (metadata) authority", Source: signalSource{signalSourceModule, "token_authority_scanner", "signals.update_authority_present"}, RequireRefs: true},
	{ID: "authority-change", Label: "Authority change since last observation", Source: signalSource{signalSourceReport, "authority_change", ""}, RequireRefs: true},
	{ID: "supply-change", Label: "Unexpected supply growth", Source: signalSource{signalSourceReport, "supply_change", ""}, RequireRefs: true},
	{ID: "wash", Label: "Wash-trading context", Source: signalSource{signalSourceReport, "trade_ledger_aggregates", ""}, RequireRefs: true},
	{ID: "address", Label: "Address behavior", Source: signalSource{signalSourceReport, "actor_investigation", "integration_run"}, RequireRefs: true},
	{ID: "liquidity", Label: "Liquidity amount + control", Source: signalSource{signalSourceReport, "lp_control", ""}, RequireRefs: true},
	{ID: "liq-move", Label: "Liquidity movement", Source: signalSource{signalSourceModule, "liquidity_movement", ""}, RequireRefs: true},
	{ID: "funding", Label: "Creator funding origin", Source: signalSource{signalSourceModule, "funding_cluster_detector", ""}, RequireRefs: true},
	{ID: "concentration", Label: "Owner-resolved holder concentration", Source: signalSource{signalSourceModule, "holder_concentration", ""}, RequireRefs: true},
	{ID: "concentration-change", Label: "Holder concentration change", Source: signalSource{signalSourceReport, "concentration_change", ""}, RequireRefs: true},
	{ID: "sniper", Label: "Sniper timing", Source: signalSource{signalSourceModule, "sniper_timing_detector", ""}, RequireRefs: true},
	{ID: "first-buyer", Label: "First-buyer linkage", Source: signalSource{signalSourceReport, "launch_forensics", "creator_linked_count"}, RequireRefs: true},
	{ID: "distribution", Label: "Launch distribution", Source: signalSource{signalSourceModule, "launch_distribution", ""}, RequireRefs: true},
	{ID: "track", Label: "Creator track record", Source: signalSource{signalSourceModule, "repeat_actor_scan", ""}, RequireRefs: true},
	{ID: "creator-sell", Label: "Creator sell behavior", Source: signalSource{signalSourceBehavior, "URD-C003", ""}, RequireRefs: true},
	{ID: "dominant-exit", Label: "Dominant-holder exit", Source: signalSource{signalSourceBehavior, "URD-C004", ""}, RequireRefs: true},
	{ID: "program", Label: "Program relations", Source: signalSource{signalSourceModule, "program_relation_scan", ""}, RequireRefs: true},
	{ID: "metadata", Label: "Metadata / impersonation", Source: signalSource{signalSourceReport, "metadata_impersonation", ""}, RequireRefs: true},
	{ID: "exploit-attempts", Label: "Repeated failed-transaction attempts", Source: signalSource{signalSourceReport, "exploit_attempts", ""}, RequireRefs: true},
	{ID: "claim", Label: "Claim / airdrop surface", Source: signalSource{signalSourceModule, "claim_surface_risk", ""}, RequireRefs: true},
	{ID: "mev", Label: "MEV exposure", Source: signalSource{signalSourceModule, "mev_shield", ""}, RequireRefs: true},
	{ID: "signed", Label: "Signed final verdict", Source: signalSource{signalSourceReport, "final_verdict", ""}, RequireRefs: false},
}

func signalDefinitionByID(id string) (signalDefinition, bool) {
	id = strings.TrimSpace(id)
	for _, def := range signalRegistry {
		if def.ID == id {
			return def, true
		}
	}
	return signalDefinition{}, false
}

func signalStateGroup(state string) string {
	switch strings.ToLower(strings.TrimSpace(state)) {
	case signalStateVerified, signalStateObserved:
		return signalGroupEvidence
	case signalStateInferred:
		return signalGroupInferred
	case signalStateWindowOpen, signalStatePending, signalStateNotInvestigated:
		return signalGroupOpen
	case signalStateNotApplicable:
		return signalGroupClosed
	default:
		return signalGroupBlocked
	}
}

func signalStateIsEvidence(state string) bool {
	return signalStateGroup(state) == signalGroupEvidence
}

func normalizeSignalState(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "verified", "verified_market_snapshot", "signed", "burned", "locked_until":
		return signalStateVerified
	case "observed", "completed", "complete", "observed_market_snapshot", "held_by_creator", "verified_or_observed":
		return signalStateObserved
	case "inferred":
		return signalStateInferred
	case "not_applicable", "n/a", "closed":
		return signalStateNotApplicable
	case "window_open", "evidence_window_open", "pending_window", "monitoring_window_active":
		return signalStateWindowOpen
	case "arm_pending", "pending", "evidence_pending", "queued", "in_progress", "collecting":
		return signalStatePending
	case "not_investigated", "not_scheduled", "not_requested", "skipped", "stored_evidence_only":
		return signalStateNotInvestigated
	case "source_unavailable", "unavailable", "unverified", "insufficient_evidence", "not_verified", "requires_trade_ledger", "collection_failed", "load_failed":
		return signalStateUnavailable
	default:
		return signalStateUnknown
	}
}

func resolveSignalSource(report map[string]any, source signalSource) (map[string]any, bool) {
	switch source.Kind {
	case signalSourceModule:
		for _, item := range dossierSlice(dossierFirst(report["evidence_arms"], report["modules"])) {
			module := dossierMap(item)
			id := strings.ToLower(strings.TrimSpace(firstNonEmptyString(
				dossierString(module["module_id"]), dossierString(module["module"]),
			)))
			if id == strings.ToLower(strings.TrimSpace(source.Key)) {
				return module, len(module) > 0
			}
		}
		return map[string]any{}, false
	case signalSourceBehavior:
		behavior := dossierMap(report["behavior_signals"])
		for _, item := range dossierSlice(behavior["signals"]) {
			signal := dossierMap(item)
			if strings.EqualFold(strings.TrimSpace(dossierString(signal["rule_id"])), strings.TrimSpace(source.Key)) {
				return signal, len(signal) > 0
			}
		}
		return map[string]any{}, false
	case signalSourceReport:
		value := dossierMap(report[source.Key])
		return value, len(value) > 0
	default:
		return map[string]any{}, false
	}
}

func signalStateFor(report map[string]any, def signalDefinition) (string, any) {
	source, present := resolveSignalSource(report, def.Source)
	if !present {
		return signalStateNotInvestigated, nil
	}

	value := any(source)
	if def.Source.Field != "" {
		field, ok := signalPathValue(source, def.Source.Field)
		if !ok {
			return signalStateUnavailable, nil
		}
		value = field
		if fieldStatus := signalFieldStatus(field); fieldStatus != "" {
			return fieldStatus, value
		}
	}

	raw := firstNonEmptyString(
		dossierString(source["evidence_status"]),
		dossierString(source["verification_status"]),
		dossierString(source["execution_status"]),
		dossierString(dossierMap(source["signals"])["execution_status"]),
		dossierString(dossierMap(source["metrics"])["execution_status"]),
		dossierString(source["state"]),
		dossierString(source["status"]),
	)
	if strings.TrimSpace(raw) != "" {
		return normalizeSignalState(raw), value
	}
	if dossierBool(source["signed"]) && strings.TrimSpace(dossierString(source["signature"])) != "" {
		return signalStateVerified, value
	}
	if available, present := source["available"].(bool); present {
		if available {
			return signalStateObserved, value
		}
		return signalStateUnavailable, value
	}
	return signalStateUnknown, value
}

func signalPathValue(source map[string]any, path string) (any, bool) {
	var current any = source
	for _, part := range strings.Split(strings.TrimSpace(path), ".") {
		part = strings.TrimSpace(part)
		if part == "" {
			return nil, false
		}
		m := dossierMap(current)
		if len(m) == 0 {
			return nil, false
		}
		next, ok := m[part]
		if !ok {
			return nil, false
		}
		current = next
	}
	return current, true
}

func signalFieldStatus(field any) string {
	m := dossierMap(field)
	if len(m) == 0 {
		return ""
	}
	raw := firstNonEmptyString(
		dossierString(m["evidence_status"]),
		dossierString(m["verification_status"]),
		dossierString(m["execution_status"]),
		dossierString(m["state"]),
		dossierString(m["status"]),
	)
	if strings.TrimSpace(raw) == "" {
		return ""
	}
	return normalizeSignalState(raw)
}

func (s signalSource) signalSourceKey() string {
	return s.Kind + "|" + strings.ToLower(strings.TrimSpace(s.Key)) + "|" + strings.ToLower(strings.TrimSpace(s.Field))
}
