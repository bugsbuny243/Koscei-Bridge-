package handlers

import (
	"os"
	"strings"
	"testing"

	"koschei/api/internal/decision"
	"koschei/api/internal/services"
)

func TestExposureLiquiditySectionProjectsCanonicalLPControlSignals(t *testing.T) {
	arm := services.SecurityRadarVerdict{
		Module:   "Liquidity Movement",
		ModuleID: services.ModuleLiquidityMovement,
		Signed:   true,
		Signals: map[string]any{
			"real_onchain_evidence":     true,
			"execution_status":          services.ArvisExecutionCompleted,
			"evidence_status":           "verified",
			"pool_address":              "pool-1",
			"pool_program":              "program-1",
			"read_slot":                 int64(4242),
			"token_vault":               "token-vault-1",
			"quote_vault":               "quote-vault-1",
			"token_reserve":             1250.5,
			"quote_reserve":             88.25,
			"reserve_snapshot_verified": true,
			"liquidity_movement_transaction_verified": true,
			"movement_evidence_status":                "verified",
			"liquidity_movement_count":                1,
			"liquidity_movement_signatures":           []string{"sig-1"},
			"liquidity_movement_actors":               []string{"actor-1"},
			"liquidity_movement_kinds":                []string{"remove_liquidity"},
		},
		Evidence: []string{"remove_liquidity VERIFIED in signature sig-1 at slot 4242."},
	}

	section := exposureSectionFromArm([]services.SecurityRadarVerdict{arm}, services.ModuleLiquidityMovement, exposureLiquiditySignalKeys())
	if verified, _ := section["verified"].(bool); !verified {
		t.Fatalf("expected liquidity section to retain verified evidence state: %#v", section)
	}
	signals, _ := section["signals"].(map[string]any)
	for _, key := range []string{
		"pool_address", "pool_program", "read_slot", "token_vault", "quote_vault",
		"token_reserve", "quote_reserve", "reserve_snapshot_verified",
		"liquidity_movement_transaction_verified", "movement_evidence_status",
		"liquidity_movement_count", "liquidity_movement_signatures",
		"liquidity_movement_actors", "liquidity_movement_kinds",
	} {
		if _, ok := signals[key]; !ok {
			t.Errorf("canonical liquidity signal %q was not projected", key)
		}
	}
}

func TestExposureShareableSummaryUsesCanonicalDecisionWithoutNumericFinalScore(t *testing.T) {
	final := services.UnifiedRadarVerdict{Grade: "-", Verdict: "no_grade_trigger", RulesetVersion: services.UnifiedRadarRulesetVersion}
	contract := decision.FromUnifiedRadar(final.Grade, final.Verdict)
	share := exposureShareableSummary("mint-1", final, contract, nil, nil)
	lines, _ := share["lines"].([]string)
	joined := strings.Join(lines, "\n")
	if !strings.Contains(joined, "Action: WITHHOLD") {
		t.Fatalf("expected canonical WITHHOLD action in shareable summary: %s", joined)
	}
	if !strings.Contains(joined, "Withhold reason: no_grade_changing_evidence") {
		t.Fatalf("expected deterministic withhold reason: %s", joined)
	}
	if strings.Contains(joined, "/100") {
		t.Fatalf("numeric final score must not return in exposure shareable summary: %s", joined)
	}
}

func TestExposureHandlerUsesCanonicalInvestigationInsteadOfCompatibilityFinal(t *testing.T) {
	raw, err := os.ReadFile("security_radar_exposure.go")
	if err != nil {
		t.Fatalf("read exposure source: %v", err)
	}
	source := string(raw)
	for _, required := range []string{
		"buildUnifiedInvestigationReport",
		"exposure_report_stored_only",
		"decision.FromUnifiedRadar",
		"exposureLiquiditySignalKeys()",
	} {
		if !strings.Contains(source, required) {
			t.Errorf("exposure wiring missing %q", required)
		}
	}
	for _, forbidden := range []string{
		"services.AnalyzeArvisRadars(",
		"services.ArvisFinalFromBundle(",
		`[]string{"pool", "reserve", "liquidity"}`,
	} {
		if strings.Contains(source, forbidden) {
			t.Errorf("legacy exposure path returned: %q", forbidden)
		}
	}
}
