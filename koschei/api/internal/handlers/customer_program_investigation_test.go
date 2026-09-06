package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestCustomerProgramInvestigationEnvelopeWithholdsMaliciousnessVerdict(t *testing.T) {
	result := customerProgramInvestigationResult{
		Target:  "Program111111111111111111111111111111111",
		Network: "solana-mainnet",
		Classification: radarTargetClassification{
			Type:   radarTargetProgram,
			Status: "verified_rpc_observation",
		},
		ProgramSecurity: services.ProgramSecuritySurface{
			Available: true,
			Status:    "available",
			Programs: []services.ProgramSecurityEvidence{{
				ProgramID:            "Program111111111111111111111111111111111",
				Available:            true,
				UpgradeAuthorityOpen: true,
			}},
		},
		Published: true,
	}

	envelope := customerProgramInvestigationEnvelope(result, false)
	verdict, ok := envelope["final_verdict"].(map[string]any)
	if !ok {
		t.Fatalf("missing final_verdict: %#v", envelope)
	}
	if verdict["signed"] != false || verdict["risk_level"] != "unknown" || verdict["grade"] != "-" {
		t.Fatalf("program authority evidence must not fabricate maliciousness verdict: %#v", verdict)
	}
	policy, ok := envelope["evidence_policy"].(map[string]any)
	if !ok || policy["upgrade_authority_is_not_intent"] != true {
		t.Fatalf("missing authority claim boundary: %#v", policy)
	}
}

func TestProgramCodeSemanticsGapIsExplicitlyVisible(t *testing.T) {
	coverage := canonicalIntegrationCoverage{Capabilities: map[string]canonicalCapabilityStatus{
		"program_code_semantics": {
			Capability:            "Program bytecode and instruction semantic analysis",
			Status:                canonicalCapabilityNotRequested,
			WiredToCanonicalRadar: true,
			RequiredForFullScan:   true,
			Source:                "program_code_semantics",
			Limitations: []string{
				"Program bytecode/instruction semantic analysis is not yet wired for arbitrary program targets.",
			},
		},
	}}
	transparency := buildInvestigationTransparency(coverage)
	if len(transparency.CollectionGaps) != 1 {
		t.Fatalf("semantic analysis gap hidden: %#v", transparency)
	}
	if transparency.CollectionGaps[0].Capability != "Program bytecode and instruction semantic analysis" {
		t.Fatalf("unexpected gap: %#v", transparency.CollectionGaps[0])
	}
}
