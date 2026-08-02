package handlers

import "testing"

func TestFinalProductIntegrationPromotesVisibleCapabilities(t *testing.T) {
	report := map[string]any{
		"full_scan_live_evidence": map[string]any{"status": "observed"},
		"exit_liquidity": map[string]any{
			"available": true,
			"status":    "complete",
			"tiers": []any{
				map[string]any{"available": true, "status": "quoted"},
			},
		},
		"program_security": map[string]any{
			"available": true,
			"status":    "complete",
			"programs": []any{
				map[string]any{"available": true, "program_id": "Program111"},
			},
		},
		"actor_investigation": map[string]any{
			"external_discovery": map[string]any{
				"available": true,
				"status":    "observed",
				"findings":  []any{"helius_created_mint_portfolio"},
			},
		},
	}

	attachFinalProductIntegrationDiagnostics(report)
	coverage, ok := report["capability_integration"].(canonicalIntegrationCoverage)
	if !ok {
		t.Fatalf("capability integration missing: %#v", report["capability_integration"])
	}
	if _, ok := coverage.Capabilities["exit_liquidity"]; !ok {
		t.Fatal("exit liquidity was not promoted into capability coverage")
	}
	if _, ok := coverage.Capabilities["program_security"]; !ok {
		t.Fatal("program security was not promoted into capability coverage")
	}
	if _, ok := coverage.Capabilities["helius_actor_discovery"]; !ok {
		t.Fatal("Helius-first actor discovery label missing")
	}
	if _, legacy := coverage.Capabilities["solscan_actor_discovery"]; legacy {
		t.Fatal("obsolete Solscan capability label remains published")
	}
	if coverage.Capabilities["exit_liquidity"].RequiredForFullScan {
		t.Fatal("quote-only exit context must not independently block a verdict")
	}
	if coverage.Capabilities["program_security"].RequiredForFullScan {
		t.Fatal("program capability context must not independently block a verdict")
	}

	defense, ok := coverage.Capabilities["defense_agent_runtime"]
	if !ok {
		t.Fatal("disabled Defense runtime is absent from capability coverage")
	}
	if defense.Status != canonicalCapabilityNotRequested {
		t.Fatalf("disabled Defense runtime status=%s, want %s", defense.Status, canonicalCapabilityNotRequested)
	}
	if !defense.WiredToCanonicalRadar || defense.RequiredForFullScan {
		t.Fatalf("disabled Defense runtime must be wired and optional: %+v", defense)
	}
	for _, orphan := range coverage.OrphanCapabilities {
		if orphan == "defense_agent_runtime" {
			t.Fatalf("disabled Defense runtime left orphan capability debt: %+v", coverage.OrphanCapabilities)
		}
	}
}

func TestFinalWalletIntegrationUsesHeliusFirstLabel(t *testing.T) {
	report := map[string]any{
		"full_scan_live_evidence": map[string]any{"status": "observed"},
		"actor_investigation": map[string]any{
			"external_discovery": map[string]any{
				"available": true,
				"status":    "observed",
				"findings":  []any{"helius_created_mint_portfolio"},
			},
		},
	}
	attachFinalWalletIntegrationDiagnostics(report)
	coverage, ok := report["capability_integration"].(canonicalIntegrationCoverage)
	if !ok {
		t.Fatalf("wallet capability integration missing: %#v", report["capability_integration"])
	}
	if _, ok := coverage.Capabilities["helius_actor_discovery"]; !ok {
		t.Fatal("wallet coverage did not publish Helius-first discovery")
	}
	if _, legacy := coverage.Capabilities["solscan_actor_discovery"]; legacy {
		t.Fatal("wallet coverage still publishes obsolete Solscan label")
	}
}
