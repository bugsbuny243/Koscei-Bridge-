package handlers

import (
	"context"
	"strings"

	"koschei/api/internal/services"
)

const customerInvestigationResponseSchemaVersion = "koschei-customer-investigation-response-v3"

func customerInvestigationStatus(final services.UnifiedRadarVerdict, hasLiveEvidence bool) string {
	if final.Signed && hasLiveEvidence {
		return "ready"
	}
	return "evidence_pending"
}

func attachCustomerAttackPath(assembly *unifiedInvestigationAssembly) {
	if assembly == nil || assembly.Report == nil {
		return
	}
	if attackPath, ok := attackPathProjectionFromReport(assembly.Report); ok {
		assembly.Report["attack_path"] = attackPath
	}
}

// attachCustomerAnalysisSummary is the single wiring point used by every
// customer-facing investigation response. The same deterministic summary is
// embedded in the canonical report and may also be exposed at the response
// top level. This prevents /api/token/scan and /api/security/radar/check from
// drifting into different result contracts.
func attachCustomerAnalysisSummary(assembly *unifiedInvestigationAssembly) map[string]any {
	if assembly == nil {
		return map[string]any{}
	}
	if assembly.Report == nil {
		assembly.Report = map[string]any{}
	}

	// Immutable snapshot diagnostics already synchronize stale projections. Run
	// the same no-I/O correction defensively for reports assembled by tests or
	// older callers, then use that exact verdict for both summary and envelope.
	if final, ok := synchronizeCanonicalUnifiedVerdict(assembly.Report); ok {
		assembly.UnifiedVerdict = final
	} else {
		assembly.Report["final_verdict"] = assembly.UnifiedVerdict
	}

	// Customer responses must expose the same evidence-backed attack-path
	// projection used by the technical parity contract. This does not add new
	// inference: the projection is derived only from the typed threat report and
	// already-collected concrete evidence references.
	attachCustomerAttackPath(assembly)

	// Preserve ARVIS as the evidence engine. The chain-neutral contract is a
	// projection of evidence ARVIS already collected; it does not replace or
	// re-grade the existing investigation.
	attachArvisIntelligenceBridge(assembly)

	// Reuse the existing typed ARVIS attack-path projection. Only pathways with
	// concrete linked evidence are copied into the chain-neutral contract; this
	// remains a capability/exposure projection and never predicts intent.
	attachArvisIntelligenceAttackPaths(assembly)

	// Threat hypotheses are an additive chain-neutral projection over those same
	// typed, evidence-linked pathways. They do not introduce a second inference
	// engine, probability, intent claim or verdict authority.
	attachArvisIntelligenceThreatHypotheses(assembly)

	// Close the chain-neutral contract only when every grade-determining rule in
	// the existing signed verdict resolves back to canonical evidence. Missing
	// links fail closed as investigate; a signed no-grade result is never turned
	// into a safety approval.
	attachArvisIntelligenceDecision(assembly)

	hasLiveEvidence := services.SecurityRadarHasLiveEvidence(assembly.Core.Bundle)
	analysisSummary := buildCustomerAnalysisSummaryV3(*assembly, hasLiveEvidence)
	assembly.Report["analysis_summary"] = analysisSummary

	// Durable intelligence memory is Drive-first and best-effort. The receipt is
	// attached after serialization so a repeated envelope projection does not
	// upload the same report twice. Neon/PostgreSQL is never used by this path.
	if _, exists := assembly.Report["intelligence_memory"]; !exists {
		target := strings.TrimSpace(assembly.Core.Request.Target)
		network := strings.TrimSpace(assembly.Core.Request.Network)
		if network == "" {
			network = "solana-mainnet"
		}
		assembly.Report["intelligence_memory"] = archiveIntelligenceMemory(context.Background(), "token_investigation", network, target, assembly.Report)
	}
	return analysisSummary
}

func customerInvestigationEnvelope(assembly unifiedInvestigationAssembly, charged bool) map[string]any {
	hasLiveEvidence := services.SecurityRadarHasLiveEvidence(assembly.Core.Bundle)
	analysisSummary := attachCustomerAnalysisSummary(&assembly)
	status := customerInvestigationStatus(assembly.UnifiedVerdict, hasLiveEvidence)
	message := "Full investigation completed."
	if status == "evidence_pending" {
		message = "Investigation completed with evidence gaps; missing evidence is not treated as a safe finding."
	}
	return map[string]any{
		"ok":                      true,
		"response_schema_version": customerInvestigationResponseSchemaVersion,
		"status":                  status,
		"message":                 message,
		"target":                  assembly.Core.Request.Target,
		"network":                 assembly.Core.Request.Network,
		"has_live_evidence":       hasLiveEvidence,
		"charged":                 charged,
		"bundle":                  assembly.Core.Bundle,
		"arms":                    assembly.Core.Arms,
		"final_verdict":           assembly.UnifiedVerdict,
		"analysis_summary":        analysisSummary,
		"investigation_report":    assembly.Report,
		"evidence_policy": map[string]any{
			"unsigned_investigation_is_not_server_failure": true,
			"missing_evidence_is_not_safe":                 true,
			"numeric_final_score_disabled":                 true,
			"numeric_rug_probability_disabled":             true,
			"distinct_rule_ids_control_compounding":        true,
		},
	}
}
