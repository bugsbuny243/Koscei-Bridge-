package handlers

// unifiedInvestigationTechnicalProjection excludes request/persistence metadata
// and keeps only the evidence-derived result that must be identical across
// public, authenticated, owner and API callers.
func unifiedInvestigationTechnicalProjection(report map[string]any) map[string]any {
	keys := []string{
		"schema_version", "target", "network", "analysis_scope", "final_verdict",
		"threat_anticipation", "investigation_coverage", "holder_distribution",
		"holder_intelligence", "holder_cluster", "holder_concentration_context",
		"launch_forensics", "market", "lp_control", "jupiter_market_context",
		"source_context", "structural_memory", "modules", "evidence_arms", "evidence",
		"behavior_signals", "trade_ledger_aggregates", "transaction_evidence",
		"evidence_references", "actor_investigation", "graph",
		"investigation_output_policy", "evidence_policy",
	}
	out := make(map[string]any, len(keys))
	for _, key := range keys {
		if value, ok := report[key]; ok {
			out[key] = value
		}
	}
	return out
}
