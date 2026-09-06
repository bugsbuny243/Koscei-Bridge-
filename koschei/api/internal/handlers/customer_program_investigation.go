package handlers

import (
	"context"
	"net/http"
	"strings"
	"time"

	"koschei/api/internal/services"
)

type customerProgramInvestigationResult struct {
	Target          string
	Network         string
	Classification  radarTargetClassification
	ProgramSecurity services.ProgramSecuritySurface
	Transparency    investigationTransparencyReport
	Memory          intelligenceMemoryReceipt
	Published       bool
}

func (h *Handler) runCustomerProgramInvestigation(ctx context.Context, target, network string, classification radarTargetClassification) customerProgramInvestigationResult {
	out := customerProgramInvestigationResult{
		Target:          target,
		Network:         network,
		Classification:  classification,
		ProgramSecurity: newProgramSecuritySurface("not_requested"),
	}
	if classification.Type != radarTargetProgram {
		return out
	}

	source := map[string]any{
		"signals": map[string]any{
			"program_id": strings.TrimSpace(target),
		},
	}
	out.ProgramSecurity = h.collectProgramSecuritySurface(ctx, network, source, services.LPControlEvidence{}, services.TokenMarketSnapshot{})
	out.Published = out.ProgramSecurity.Available || len(out.ProgramSecurity.Programs) > 0

	coverage := canonicalIntegrationCoverage{
		SchemaVersion:     "koschei-capability-integration-v1",
		LiveScanRequested: true,
		Capabilities: map[string]canonicalCapabilityStatus{
			"program_security": canonicalStatusFromRaw(
				"Solana program authority and deployment-age evidence",
				out.ProgramSecurity,
				true,
				true,
				"program_security",
			),
			"program_code_semantics": {
				Capability:            "Program bytecode and instruction semantic analysis",
				Status:                canonicalCapabilityNotRequested,
				WiredToCanonicalRadar: true,
				RequiredForFullScan:   true,
				EvidenceBacked:        false,
				Source:                "program_code_semantics",
				Limitations: []string{
					"Program bytecode/instruction semantic analysis is not yet wired for arbitrary program targets; absence of a finding here is not evidence that hidden execution behavior is safe.",
				},
			},
		},
		OrphanCapabilities: []string{},
		Policy: map[string]any{
			"full_scan_cannot_claim_complete_when_required_capability_is_unavailable": true,
		},
	}
	recountFinalProductCoverage(&coverage)
	out.Transparency = buildInvestigationTransparency(coverage)

	memoryPayload := map[string]any{
		"schema_version":             "koschei-program-investigation-v1",
		"target":                     target,
		"network":                    network,
		"target_classification":      classification,
		"program_security":           out.ProgramSecurity,
		"investigation_transparency": out.Transparency,
	}
	out.Memory = h.archiveIntelligenceMemory(ctx, "program_investigation", network, target, memoryPayload)
	return out
}

func customerProgramInvestigationEnvelope(result customerProgramInvestigationResult, charged bool, historical ...intelligenceMemoryReadReceipt) map[string]any {
	status := "evidence_pending"
	if result.Published {
		status = "evidence_available_with_gaps"
	}
	history := intelligenceMemoryReadReceipt{
		Status:      "not_requested",
		Backend:     "google_drive",
		Limitations: []string{},
	}
	if len(historical) > 0 {
		history = historical[0]
	}
	return map[string]any{
		"ok":                         true,
		"status":                     status,
		"investigation_kind":         "program_security",
		"schema_version":             "koschei-program-investigation-v1",
		"target":                     result.Target,
		"network":                    result.Network,
		"target_classification":      result.Classification,
		"program_security":           result.ProgramSecurity,
		"investigation_transparency": result.Transparency,
		"historical_memory":          history,
		"intelligence_memory":        result.Memory,
		"charged":                    charged,
		"final_verdict": map[string]any{
			"grade":          "-",
			"risk_index":     nil,
			"risk_level":     "unknown",
			"signed":         false,
			"verdict":        "Program authority/deployment evidence is available, but arbitrary-program code semantics are not yet complete enough for a maliciousness verdict.",
			"recommendation": "review_program_authority_and_semantic_gaps",
		},
		"evidence_policy": map[string]any{
			"no_evidence_no_claim":                       true,
			"upgrade_authority_is_not_intent":            true,
			"unknown_is_not_safe":                        true,
			"numeric_final_score_disabled":               true,
			"historical_memory_cannot_override_live_evidence": true,
			"durable_memory_backend":                     "google_drive",
			"neon_intelligence_persistence":              false,
		},
	}
}

func (h *Handler) securityRadarProgramCheck(w http.ResponseWriter, r *http.Request, authSubject, claimEmail, target, network string, classification radarTargetClassification) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	history := h.loadLatestIntelligenceMemory(ctx, "program_investigation", network, target)
	result := h.runCustomerProgramInvestigation(ctx, target, network, classification)

	charged := false
	if result.Published {
		if err := h.consumePremiumOutput(authSubject, claimEmail, "security_radar_program_check"); err != nil {
			writeJSON(w, http.StatusPaymentRequired, insufficientOutputsResponse())
			return
		}
		charged = true
	}
	h.logTool(claimEmail, "security_radar_program_check", map[bool]string{true: "ready", false: "evidence_pending"}[result.Published])
	h.trackEvent(claimEmail, "security_radar_program_check", r.URL.Path)
	writeJSON(w, http.StatusOK, customerProgramInvestigationEnvelope(result, charged, history))
}

func (h *Handler) ownerUnifiedProgramRadar(w http.ResponseWriter, r *http.Request, target, network string, classification radarTargetClassification) {
	ctx, cancel := context.WithTimeout(r.Context(), 90*time.Second)
	defer cancel()
	history := h.loadLatestIntelligenceMemory(ctx, "program_investigation", network, target)
	result := h.runCustomerProgramInvestigation(ctx, target, network, classification)
	writeJSON(w, http.StatusOK, customerProgramInvestigationEnvelope(result, false, history))
}
