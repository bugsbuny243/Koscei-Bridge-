package handlers

import (
	"encoding/json"
	"fmt"
	"strings"

	"koschei/api/internal/services"
)

const (
	canonicalCapabilityActive       = "active"
	canonicalCapabilityPartial      = "partial"
	canonicalCapabilityUnavailable  = "unavailable"
	canonicalCapabilityNotRequested = "not_requested"
)

type canonicalCapabilityStatus struct {
	Capability            string   `json:"capability"`
	Status                string   `json:"status"`
	WiredToCanonicalRadar bool     `json:"wired_to_canonical_radar"`
	RequiredForFullScan   bool     `json:"required_for_full_scan"`
	EvidenceBacked        bool     `json:"evidence_backed"`
	Source                string   `json:"source,omitempty"`
	Limitations           []string `json:"limitations"`
}

type canonicalIntegrationCoverage struct {
	SchemaVersion             string                               `json:"schema_version"`
	OverallStatus             string                               `json:"overall_status"`
	LiveScanRequested         bool                                 `json:"live_scan_requested"`
	Capabilities              map[string]canonicalCapabilityStatus `json:"capabilities"`
	RequiredCapabilityCount   int                                  `json:"required_capability_count"`
	ActiveRequiredCount       int                                  `json:"active_required_count"`
	PartialRequiredCount      int                                  `json:"partial_required_count"`
	UnavailableRequiredCount  int                                  `json:"unavailable_required_count"`
	NotRequestedRequiredCount int                                  `json:"not_requested_required_count"`
	OrphanCapabilityCount     int                                  `json:"orphan_capability_count"`
	OrphanCapabilities        []string                             `json:"orphan_capabilities"`
	Policy                    map[string]any                       `json:"policy"`
}

// attachCanonicalInvestigationDiagnostics mutates the exact canonical report
// before immutable snapshotting. A production module therefore has to expose its
// reachability and evidence status in the same payload returned to every caller.
func attachCanonicalInvestigationDiagnostics(report map[string]any) {
	if report == nil {
		return
	}
	actor := canonicalMap(report["actor_investigation"])
	if len(actor) > 0 {
		if _, attached := actor["evidence_graph"]; !attached {
			if dossier, ok := canonicalActorDossier(actor["dossier"]); ok {
				actor["evidence_graph"] = services.BuildActorEvidenceGraph(dossier)
			}
		}
		report["actor_investigation"] = actor
	}
	report["capability_integration"] = buildCanonicalIntegrationCoverage(report)
}

func buildCanonicalIntegrationCoverage(report map[string]any) canonicalIntegrationCoverage {
	live := canonicalLiveScanRequested(report)
	out := canonicalIntegrationCoverage{
		SchemaVersion:      "koschei-capability-integration-v1",
		OverallStatus:      "complete",
		LiveScanRequested:  live,
		Capabilities:       map[string]canonicalCapabilityStatus{},
		OrphanCapabilities: []string{},
		Policy: map[string]any{
			"feature_without_trigger_is_orphan":                                       true,
			"feature_without_evidence_persistence_is_partial":                         true,
			"feature_without_report_contract_is_partial":                              true,
			"full_scan_cannot_claim_complete_when_required_capability_is_unavailable": true,
			"safe_check_can_leave_live_capabilities_not_requested":                    true,
		},
	}
	put := func(key string, item canonicalCapabilityStatus) {
		if item.Limitations == nil {
			item.Limitations = []string{}
		}
		out.Capabilities[key] = item
		if !item.WiredToCanonicalRadar {
			out.OrphanCapabilityCount++
			out.OrphanCapabilities = append(out.OrphanCapabilities, key)
		}
		if !item.RequiredForFullScan {
			return
		}
		out.RequiredCapabilityCount++
		switch item.Status {
		case canonicalCapabilityActive:
			out.ActiveRequiredCount++
		case canonicalCapabilityPartial:
			out.PartialRequiredCount++
		case canonicalCapabilityNotRequested:
			out.NotRequestedRequiredCount++
		default:
			out.UnavailableRequiredCount++
		}
	}

	modules := canonicalSlice(report["modules"])
	put("arvis_14_arm_engine", canonicalStatusFromCount(
		"ARVIS 14-arm evidence engine", len(modules), 14, true,
		"modules/evidence_arms", "Canonical report did not expose all 14 architecture arms.",
	))
	put("holder_intelligence", canonicalStatusFromRaw("Owner-resolved holder intelligence", report["holder_intelligence"], live, true, "holder_intelligence"))
	put("holder_cluster", canonicalStatusFromRaw("Holder cluster and flow intelligence", report["holder_cluster"], live, true, "holder_cluster"))
	put("launch_forensics", canonicalStatusFromRaw("Launch forensics", report["launch_forensics"], live, true, "launch_forensics"))
	put("lp_control", canonicalStatusFromRaw("Liquidity and LP control", report["lp_control"], live, true, "lp_control"))
	put("jupiter_market_context", canonicalStatusFromRaw("Jupiter route and exit context", report["jupiter_market_context"], live, false, "jupiter_market_context"))
	put("threat_anticipation", canonicalStatusFromRaw("Threat anticipation", report["threat_anticipation"], live, true, "threat_anticipation"))
	put("deterministic_unified_verdict", canonicalStatusFromSignedVerdict("Deterministic Unified Verdict", report["final_verdict"], true, "final_verdict"))

	actor := canonicalMap(report["actor_investigation"])
	put("creator_target_transition", canonicalStatusFromRaw("Mint to creator target transition", actor["current_creator_relation"], live, true, "actor_investigation.current_creator_relation"))
	put("solscan_actor_discovery", canonicalStatusFromRaw("Solscan actor discovery and attribution", actor["external_discovery"], live, true, "actor_investigation.external_discovery"))
	external := canonicalMap(actor["external_discovery"])
	put("created_mint_portfolio", canonicalStatusFromRaw("Created-mint portfolio discovery and RPC verification", external["created_mint_portfolio"], live, true, "actor_investigation.external_discovery.created_mint_portfolio"))
	put("funding_origin", canonicalStatusFromRaw("Actor funding origin", actor["funding_origin"], live, true, "actor_investigation.funding_origin"))
	put("actor_live_transaction_evidence", canonicalStatusFromRaw("Actor live transaction evidence", actor["actor_live_evidence"], live, true, "actor_investigation.actor_live_evidence"))
	put("initial_distribution", canonicalStatusFromRaw("Mint-specific initial recipient investigation", actor["current_token_distribution"], live, true, "actor_investigation.current_token_distribution"))
	put("persistent_actor_dossier", canonicalStatusFromDossier(actor["dossier"], live))
	put("actor_evidence_graph", canonicalStatusFromGraph(actor["evidence_graph"], live))
	put("actor_ruleset", canonicalStatusFromSignedVerdict("Deterministic actor ruleset", actor["rule_verdict"], true, "actor_investigation.rule_verdict"))
	put("defense_agent_runtime", canonicalStatusFromRaw("Solana Defense shadow runtime", report["defense_agent_runtime"], live, false, "defense_agent_runtime"))
	put("immutable_dossier_snapshot", canonicalCapabilityStatus{
		Capability: "Immutable dossier snapshot", Status: canonicalCapabilityActive,
		WiredToCanonicalRadar: true, RequiredForFullScan: false, EvidenceBacked: true,
		Source:      "persistDossierSourceSnapshot",
		Limitations: []string{"Persistence remains best-effort when the database or signed verdict is unavailable."},
	})

	if !live {
		out.OverallStatus = "stored_or_preflight_projection"
		return out
	}
	switch {
	case out.UnavailableRequiredCount > 0 || out.OrphanCapabilityCount > 0:
		out.OverallStatus = "blocked"
	case out.PartialRequiredCount > 0 || out.NotRequestedRequiredCount > 0:
		out.OverallStatus = "partial"
	default:
		out.OverallStatus = "complete"
	}
	return out
}

func canonicalStatusFromCount(name string, observed, expected int, required bool, source, limitation string) canonicalCapabilityStatus {
	item := canonicalCapabilityStatus{Capability: name, WiredToCanonicalRadar: true, RequiredForFullScan: required, Source: source, Limitations: []string{}}
	switch {
	case observed >= expected:
		item.Status, item.EvidenceBacked = canonicalCapabilityActive, true
	case observed > 0:
		item.Status, item.EvidenceBacked = canonicalCapabilityPartial, true
		item.Limitations = append(item.Limitations, limitation)
	default:
		item.Status = canonicalCapabilityUnavailable
		item.Limitations = append(item.Limitations, limitation)
	}
	return item
}

func canonicalStatusFromRaw(name string, raw any, live, required bool, source string) canonicalCapabilityStatus {
	item := canonicalCapabilityStatus{
		Capability: name, WiredToCanonicalRadar: raw != nil,
		RequiredForFullScan: required, Source: source, Limitations: []string{},
	}
	value := canonicalMap(raw)
	if len(value) == 0 {
		if !live {
			item.Status, item.WiredToCanonicalRadar = canonicalCapabilityNotRequested, true
			return item
		}
		item.Status = canonicalCapabilityUnavailable
		item.Limitations = append(item.Limitations, "Canonical report section is absent or empty.")
		return item
	}
	status := strings.ToLower(strings.TrimSpace(canonicalString(value["status"])))
	item.Limitations = canonicalLimitations(value["limitations"])
	item.EvidenceBacked = canonicalObjectHasEvidence(value)
	if strings.Contains(status, "not_requested") || strings.Contains(status, "stored_evidence_only") {
		item.Status = canonicalCapabilityNotRequested
		return item
	}
	if strings.Contains(status, "partial") || strings.Contains(status, "bounded") || strings.Contains(status, "insufficient") || strings.Contains(status, "degraded") {
		item.Status = canonicalCapabilityPartial
		return item
	}
	if strings.Contains(status, "failed") || strings.Contains(status, "unavailable") || strings.Contains(status, "not_configured") || strings.Contains(status, "required") || strings.Contains(status, "unresolved") {
		if item.EvidenceBacked {
			item.Status = canonicalCapabilityPartial
		} else {
			item.Status = canonicalCapabilityUnavailable
		}
		return item
	}
	if canonicalBool(value["available"]) || strings.Contains(status, "complete") || strings.Contains(status, "verified") || strings.Contains(status, "evidence_backed") || strings.Contains(status, "observed") || strings.Contains(status, "persisted") {
		item.Status = canonicalCapabilityActive
		item.EvidenceBacked = item.EvidenceBacked || canonicalBool(value["available"]) || strings.Contains(status, "verified") || strings.Contains(status, "evidence")
		return item
	}
	if item.EvidenceBacked {
		item.Status = canonicalCapabilityActive
		return item
	}
	item.Status = canonicalCapabilityPartial
	item.Limitations = append(item.Limitations, "Capability is connected but did not expose a terminal evidence status.")
	return item
}

func canonicalStatusFromSignedVerdict(name string, raw any, required bool, source string) canonicalCapabilityStatus {
	item := canonicalCapabilityStatus{Capability: name, WiredToCanonicalRadar: raw != nil, RequiredForFullScan: required, Source: source, Limitations: []string{}}
	value := canonicalMap(raw)
	ruleset := strings.TrimSpace(firstNonEmptyString(canonicalString(value["ruleset_version"]), canonicalString(value["rule_version"])))
	if canonicalBool(value["signed"]) && strings.TrimSpace(canonicalString(value["signature"])) != "" && ruleset != "" {
		item.Status, item.EvidenceBacked = canonicalCapabilityActive, true
		return item
	}
	if len(value) > 0 && ruleset != "" {
		item.Status = canonicalCapabilityPartial
		item.Limitations = append(item.Limitations, "Ruleset executed but the signed verdict envelope is incomplete.")
		return item
	}
	item.Status = canonicalCapabilityUnavailable
	item.Limitations = append(item.Limitations, "Signed deterministic verdict is missing.")
	return item
}

func canonicalStatusFromDossier(raw any, live bool) canonicalCapabilityStatus {
	item := canonicalCapabilityStatus{Capability: "Persistent actor dossier", WiredToCanonicalRadar: raw != nil, RequiredForFullScan: true, Source: "actor_investigation.dossier", Limitations: []string{}}
	dossier, ok := canonicalActorDossier(raw)
	if !ok {
		if !live {
			item.Status, item.WiredToCanonicalRadar = canonicalCapabilityNotRequested, true
		} else {
			item.Status = canonicalCapabilityUnavailable
			item.Limitations = append(item.Limitations, "Actor dossier could not be decoded.")
		}
		return item
	}
	item.EvidenceBacked = len(dossier.Evidence) > 0
	if item.EvidenceBacked || len(dossier.Tokens) > 0 || len(dossier.RelatedActors) > 0 {
		item.Status = canonicalCapabilityActive
	} else if live {
		item.Status = canonicalCapabilityPartial
		item.Limitations = append(item.Limitations, "Dossier is connected but no persistent actor relation was produced in this run.")
	} else {
		item.Status = canonicalCapabilityNotRequested
	}
	return item
}

func canonicalStatusFromGraph(raw any, live bool) canonicalCapabilityStatus {
	item := canonicalCapabilityStatus{Capability: "Persistent actor evidence graph", WiredToCanonicalRadar: raw != nil, RequiredForFullScan: true, Source: "actor_investigation.evidence_graph", Limitations: []string{}}
	value := canonicalMap(raw)
	if canonicalBool(value["available"]) || canonicalInt(value["edge_count"]) > 0 {
		item.Status, item.EvidenceBacked = canonicalCapabilityActive, true
	} else if !live {
		item.Status, item.WiredToCanonicalRadar = canonicalCapabilityNotRequested, true
	} else if raw != nil {
		item.Status = canonicalCapabilityPartial
		item.Limitations = append(item.Limitations, "Graph projector is connected but no evidence edge was available.")
	} else {
		item.Status = canonicalCapabilityUnavailable
	}
	return item
}

func canonicalLiveScanRequested(report map[string]any) bool {
	live := canonicalMap(report["full_scan_live_evidence"])
	status := strings.ToLower(strings.TrimSpace(canonicalString(live["status"])))
	return status != "" && status != "not_requested" && status != "stored_evidence_only" && status != "not_requested_preflight"
}

func canonicalActorDossier(raw any) (services.ActorDefenseDossier, bool) {
	if dossier, ok := raw.(services.ActorDefenseDossier); ok {
		return dossier, strings.TrimSpace(dossier.Wallet) != ""
	}
	encoded, err := json.Marshal(raw)
	if err != nil || len(encoded) == 0 || string(encoded) == "null" {
		return services.ActorDefenseDossier{}, false
	}
	var dossier services.ActorDefenseDossier
	if json.Unmarshal(encoded, &dossier) != nil || strings.TrimSpace(dossier.Wallet) == "" {
		return services.ActorDefenseDossier{}, false
	}
	return dossier, true
}

func canonicalMap(raw any) map[string]any {
	if value, ok := raw.(map[string]any); ok && value != nil {
		return value
	}
	encoded, err := json.Marshal(raw)
	if err != nil || len(encoded) == 0 || string(encoded) == "null" {
		return map[string]any{}
	}
	value := map[string]any{}
	if json.Unmarshal(encoded, &value) != nil {
		return map[string]any{}
	}
	return value
}

func canonicalSlice(raw any) []any {
	if value, ok := raw.([]any); ok {
		return value
	}
	encoded, err := json.Marshal(raw)
	if err != nil || len(encoded) == 0 {
		return []any{}
	}
	value := []any{}
	if json.Unmarshal(encoded, &value) != nil {
		return []any{}
	}
	return value
}

func canonicalLimitations(raw any) []string {
	out := []string{}
	for _, item := range canonicalSlice(raw) {
		value := strings.TrimSpace(fmt.Sprint(item))
		if value != "" && value != "<nil>" {
			out = append(out, value)
		}
	}
	return out
}

func canonicalObjectHasEvidence(value map[string]any) bool {
	for _, key := range []string{"evidence", "findings", "transactions", "recipients", "candidates", "verified_candidates", "nodes", "edges", "triggered_rules", "watch_flags"} {
		if len(canonicalSlice(value[key])) > 0 {
			return true
		}
	}
	for _, key := range []string{"evidence_persisted", "transactions_parsed", "parsed_evidence", "edge_count", "verified_evidence_count", "candidates_verified", "verified_evidence_persisted"} {
		if canonicalInt(value[key]) > 0 {
			return true
		}
	}
	return false
}

func canonicalString(raw any) string {
	if raw == nil {
		return ""
	}
	value := strings.TrimSpace(fmt.Sprint(raw))
	if value == "<nil>" {
		return ""
	}
	return value
}

func canonicalBool(raw any) bool {
	if value, ok := raw.(bool); ok {
		return value
	}
	return strings.EqualFold(strings.TrimSpace(fmt.Sprint(raw)), "true")
}

func canonicalInt(raw any) int {
	switch value := raw.(type) {
	case int:
		return value
	case int64:
		return int(value)
	case float64:
		return int(value)
	default:
		var parsed int
		_, _ = fmt.Sscan(strings.TrimSpace(fmt.Sprint(raw)), &parsed)
		return parsed
	}
}
