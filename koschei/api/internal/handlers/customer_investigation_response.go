package handlers

import "koschei/api/internal/services"

const customerInvestigationResponseSchemaVersion = "koschei-customer-investigation-response-v2"

func customerInvestigationStatus(final services.UnifiedRadarVerdict, hasLiveEvidence bool) string {
	if final.Signed && hasLiveEvidence {
		return "ready"
	}
	return "evidence_pending"
}

func customerInvestigationEnvelope(assembly unifiedInvestigationAssembly, charged bool) map[string]any {
	hasLiveEvidence := services.SecurityRadarHasLiveEvidence(assembly.Core.Bundle)
	status := customerInvestigationStatus(assembly.UnifiedVerdict, hasLiveEvidence)
	message := "Full investigation completed."
	if status == "evidence_pending" {
		message = "Investigation completed with evidence gaps; missing evidence is not treated as a safe finding."
	}
	analysisSummary := buildCustomerAnalysisSummary(assembly, hasLiveEvidence)
	if assembly.Report == nil {
		assembly.Report = map[string]any{}
	}
	assembly.Report["analysis_summary"] = analysisSummary
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
		},
	}
}
