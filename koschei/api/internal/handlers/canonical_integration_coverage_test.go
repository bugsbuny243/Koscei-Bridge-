package handlers

import (
	"fmt"
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestAttachCanonicalInvestigationDiagnosticsBuildsActorGraphAndCompleteCoverage(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	modules := make([]map[string]any, 14)
	for index := range modules {
		modules[index] = map[string]any{"module_id": fmt.Sprintf("module_%02d", index+1), "status": "complete"}
	}
	dossier := services.ActorDefenseDossier{
		Wallet: "Creator111", Network: "solana-mainnet",
		Tokens:        []services.ActorDefenseTokenObservation{{Mint: "Mint111", Roles: []string{"creator_deployer"}, CreatorSignature: "CreateSig111"}},
		RelatedActors: []services.ActorDefenseRelatedActor{},
		Evidence: []services.ActorDefenseEvidenceRecord{{
			Network: "solana-mainnet", ActorWallet: "Creator111",
			CounterpartKind: "token", CounterpartID: "Mint111", Relation: "created_token",
			VerificationStatus: "verified", EvidenceKey: "created:Mint111", Source: "solana_jsonparsed_instruction",
			Signature: "CreateSig111", Slot: 100, ObservedAt: now, TokenMint: "Mint111", OccurrenceCount: 1, Metadata: map[string]any{},
		}},
		Coverage: map[string]any{"persisted_evidence": 1}, Policy: map[string]any{}, GeneratedAt: now,
	}
	report := map[string]any{
		"modules":                 modules,
		"holder_intelligence":     map[string]any{"status": "evidence_backed", "available": true},
		"holder_cluster":          map[string]any{"status": "complete", "available": true},
		"launch_forensics":        map[string]any{"status": "observed", "available": true},
		"lp_control":              map[string]any{"status": "verified", "available": true},
		"jupiter_market_context":  map[string]any{"status": "complete", "available": true},
		"threat_anticipation":     map[string]any{"status": "complete", "findings": []any{"path observed"}},
		"final_verdict":           map[string]any{"signed": true, "signature": "UnifiedSig111", "ruleset_version": "rules-v1"},
		"full_scan_live_evidence": map[string]any{"status": "complete", "transactions": []any{"tx"}},
		"defense_agent_runtime":   map[string]any{"status": "complete"},
		"actor_investigation": map[string]any{
			"dossier":                  dossier,
			"current_creator_relation": map[string]any{"status": "verified", "evidence": []any{"creator relation"}},
			"external_discovery": map[string]any{
				"status": "complete_persisted", "evidence_persisted": 1,
				"created_mint_portfolio": map[string]any{
					"status": "verified", "candidates_verified": 1, "verified_evidence_persisted": 1,
				},
			},
			"funding_origin":             map[string]any{"status": "verified", "verification_status": "verified"},
			"actor_live_evidence":        map[string]any{"status": "complete", "evidence_persisted": 1},
			"current_token_distribution": map[string]any{"status": "verified", "recipients": []any{"Recipient111"}},
			"rule_verdict":               map[string]any{"signed": true, "signature": "ActorSig111", "ruleset_version": "actor-rules-v1"},
		},
	}

	attachCanonicalInvestigationDiagnostics(report)
	actor := canonicalMap(report["actor_investigation"])
	graph := canonicalMap(actor["evidence_graph"])
	if canonicalInt(graph["edge_count"]) != 1 || !canonicalBool(graph["available"]) {
		t.Fatalf("actor graph was not attached from persistent evidence: %#v", graph)
	}
	coverage, ok := report["capability_integration"].(canonicalIntegrationCoverage)
	if !ok {
		t.Fatalf("capability coverage was not attached: %#v", report["capability_integration"])
	}
	if coverage.OverallStatus != "complete" || coverage.OrphanCapabilityCount != 0 || coverage.UnavailableRequiredCount != 0 {
		t.Fatalf("expected fully connected canonical report, got %#v", coverage)
	}
	if coverage.Capabilities["created_mint_portfolio"].Status != canonicalCapabilityActive {
		t.Fatalf("created mint portfolio not classified active: %#v", coverage.Capabilities["created_mint_portfolio"])
	}
}

func TestCanonicalIntegrationCoverageBlocksLiveReportWhenCapabilityFallsOutOfPipeline(t *testing.T) {
	modules := make([]map[string]any, 14)
	for index := range modules {
		modules[index] = map[string]any{"module_id": fmt.Sprintf("module_%02d", index+1)}
	}
	report := map[string]any{
		"modules":                 modules,
		"holder_intelligence":     map[string]any{"status": "complete", "available": true},
		"holder_cluster":          map[string]any{"status": "complete", "available": true},
		"launch_forensics":        map[string]any{"status": "complete", "available": true},
		"lp_control":              map[string]any{"status": "complete", "available": true},
		"threat_anticipation":     map[string]any{"status": "complete", "available": true},
		"final_verdict":           map[string]any{"signed": true, "signature": "UnifiedSig111", "ruleset_version": "rules-v1"},
		"full_scan_live_evidence": map[string]any{"status": "complete"},
		"actor_investigation": map[string]any{
			"dossier":                  services.ActorDefenseDossier{Wallet: "Creator111"},
			"current_creator_relation": map[string]any{"status": "verified"},
			"external_discovery":       map[string]any{"status": "complete_persisted"},
			// created_mint_portfolio is intentionally absent: this must be visible as an orphan.
			"funding_origin":             map[string]any{"status": "verified"},
			"actor_live_evidence":        map[string]any{"status": "complete"},
			"current_token_distribution": map[string]any{"status": "complete"},
			"rule_verdict":               map[string]any{"signed": true, "signature": "ActorSig111", "ruleset_version": "actor-rules-v1"},
		},
	}
	attachCanonicalInvestigationDiagnostics(report)
	coverage := report["capability_integration"].(canonicalIntegrationCoverage)
	if coverage.OverallStatus != "blocked" {
		t.Fatalf("live report with missing required capability was not blocked: %#v", coverage)
	}
	if coverage.OrphanCapabilityCount == 0 || coverage.Capabilities["created_mint_portfolio"].WiredToCanonicalRadar {
		t.Fatalf("missing created-mint pipeline was not exposed as orphan: %#v", coverage.Capabilities["created_mint_portfolio"])
	}
}

func TestCanonicalIntegrationCoverageAllowsStoredProjectionToSkipLiveCollectors(t *testing.T) {
	report := map[string]any{
		"modules":                 []map[string]any{},
		"full_scan_live_evidence": map[string]any{"status": "not_requested"},
		"actor_investigation":     map[string]any{"dossier": services.ActorDefenseDossier{Wallet: "Creator111"}},
	}
	attachCanonicalInvestigationDiagnostics(report)
	coverage := report["capability_integration"].(canonicalIntegrationCoverage)
	if coverage.LiveScanRequested || coverage.OverallStatus != "stored_or_preflight_projection" {
		t.Fatalf("stored projection was treated as a failed full scan: %#v", coverage)
	}
}
