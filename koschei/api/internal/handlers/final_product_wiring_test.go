package handlers

import "testing"

func TestNormalizeFinalProductCapabilityCoverage(t *testing.T) {
	report := map[string]any{
		"full_scan_live_evidence": map[string]any{"status": "complete"},
		"exit_liquidity": map[string]any{
			"available": true,
			"status":    "complete",
			"tiers":     []any{map[string]any{"status": "quoted"}},
		},
		"program_security": map[string]any{
			"available": true,
			"status":    "complete",
			"programs":  []any{map[string]any{"available": true}},
		},
		"capability_integration": canonicalIntegrationCoverage{
			SchemaVersion:     "koschei-capability-integration-v1",
			OverallStatus:     "blocked",
			LiveScanRequested: true,
			Capabilities: map[string]canonicalCapabilityStatus{
				"solscan_actor_discovery": {
					Capability:            "Solscan actor discovery and attribution",
					Status:                canonicalCapabilityActive,
					WiredToCanonicalRadar: true,
					RequiredForFullScan:   true,
					EvidenceBacked:        true,
				},
				"defense_agent_runtime": {
					Capability:            "Solana Defense shadow runtime",
					Status:                canonicalCapabilityUnavailable,
					WiredToCanonicalRadar: false,
					RequiredForFullScan:   false,
				},
			},
		},
	}

	normalizeFinalProductCapabilityCoverage(report)
	coverage := report["capability_integration"].(canonicalIntegrationCoverage)

	for _, key := range []string{"exit_liquidity", "program_security", "helius_actor_discovery", "defense_agent_runtime"} {
		item, ok := coverage.Capabilities[key]
		if !ok {
			t.Fatalf("capability %s missing", key)
		}
		if !item.WiredToCanonicalRadar {
			t.Fatalf("capability %s remains orphaned: %+v", key, item)
		}
	}
	if _, exists := coverage.Capabilities["solscan_actor_discovery"]; exists {
		t.Fatal("stale Solscan capability key remains")
	}
	defense := coverage.Capabilities["defense_agent_runtime"]
	if defense.Status != canonicalCapabilityNotRequested || defense.RequiredForFullScan {
		t.Fatalf("disabled Defense OS must not block core scan: %+v", defense)
	}
	if coverage.OrphanCapabilityCount != 0 {
		t.Fatalf("unexpected orphan capabilities: %+v", coverage.OrphanCapabilities)
	}
}
