package services

import (
	"testing"
	"time"
)

func TestUnavailableArvisArmIsNeverSigned(t *testing.T) {
	req := SecurityRadarRequest{Target: "target", Network: "solana-mainnet"}
	arm := unavailableArm("Liquidity Movement", ModuleLiquidityMovement, req, time.Now().UTC().Format(time.RFC3339), "missing reserve history")
	if arm.Signed {
		t.Fatal("unavailable arm must not be signed")
	}
	if arm.RiskIndex != 0 || arm.Grade != "-" || arm.Signature != "" {
		t.Fatalf("unexpected unavailable arm: %#v", arm)
	}
	if available, _ := arm.Signals["arm_evidence_available"].(bool); available {
		t.Fatal("unavailable arm reported evidence")
	}
}

func TestEvidenceArmSignsEvidenceWithoutIssuingGrade(t *testing.T) {
	req := SecurityRadarRequest{Target: "target", Network: "solana-mainnet"}
	signals := map[string]any{"real_onchain_evidence": true, "arm_evidence_available": true}
	arm := evidenceArm("Token Authority Scanner", ModuleTokenAuthorityScanner, req, 81, signals, []string{"parsed mint evidence"}, time.Now().UTC().Format(time.RFC3339))
	if !arm.Signed || arm.Signature == "" {
		t.Fatalf("evidence arm should be signed: %#v", arm)
	}
	if arm.RiskIndex != 0 || arm.Grade != "-" || arm.RiskLevel != "evidence_only" {
		t.Fatalf("evidence arm issued a score or grade: %#v", arm)
	}
	if disabled, _ := arm.Signals["numeric_score_disabled"].(bool); !disabled {
		t.Fatalf("numeric-score policy missing: %#v", arm.Signals)
	}
	if arm.Signals["actor_ruleset_version"] != ActorDefenseRulesetVersion {
		t.Fatalf("actor ruleset missing: %#v", arm.Signals)
	}
	if arm.Signals["unified_radar_ruleset"] != UnifiedRadarRulesetVersion {
		t.Fatalf("unified ruleset missing: %#v", arm.Signals)
	}
	if arm.Signals["evidence_row_standard"] == "" {
		t.Fatalf("evidence-row standard missing: %#v", arm.Signals)
	}
}

func TestFinalArvisArmIsOnlyCompatibilityAdapter(t *testing.T) {
	req := SecurityRadarRequest{Target: "target", Network: "solana-mainnet"}
	generatedAt := time.Now().UTC().Format(time.RFC3339)
	first := evidenceArm("Program Relation Scan", ModuleProgramRelationScan, req, 20, map[string]any{"real_onchain_evidence": true}, []string{"owner evidence"}, generatedAt)
	second := evidenceArm("Holder Concentration", ModuleHolderConcentration, req, 72, map[string]any{"real_onchain_evidence": true}, []string{"holder evidence"}, generatedAt)
	final := buildFinalArm(req, []SecurityRadarVerdict{first, second}, generatedAt)
	if final.Signed || final.Grade != "-" || final.RiskIndex != 0 {
		t.Fatalf("compatibility final issued a verdict: %#v", final)
	}
	if source, _ := final.Signals["verdict_source"].(string); source != "EvaluateUnifiedRadarVerdict" {
		t.Fatalf("unexpected verdict source: %q", source)
	}
	if _, exists := final.Signals["winning_arm"]; exists {
		t.Fatalf("compatibility final selected a winning arm: %#v", final.Signals)
	}
}

func TestArvisBundleExposesFourteenArms(t *testing.T) {
	arms := make([]SecurityRadarVerdict, 14)
	bundle := SecurityRadarBundle{Metadata: map[string]any{"arvis_arms": arms}}
	got := ArvisArmsFromBundle(bundle)
	if len(got) != 14 {
		t.Fatalf("expected 14 arms, got %d", len(got))
	}
}

func TestArvisPumpAndRaydiumApplicabilityUsesEvidenceNotMode(t *testing.T) {
	req := SecurityRadarRequest{Target: "9cRCn9rGT8V2imeM2BaKs13yhMEais3ruM3rPvTGpump", Network: "solana-mainnet", Mode: "owner_manual"}
	profile := radarEvidenceProfile{LiveRPC: true, AccountExists: true, AccountOwner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", RecentSignatureCount: 12, DataQuality: "live_rpc_evidence", EvidenceStatus: "verified_rpc_observation"}
	pump := buildPumpProgramApplicabilityArm(req, profile, "2026-07-18T00:00:00Z")
	raydium := buildRaydiumProgramApplicabilityArm(req, profile, "2026-07-18T00:00:00Z")
	if !pump.Signed {
		t.Fatalf("pump arm did not build from evidence in manual mode: %#v", pump)
	}
	if status := arvisSignalString(raydium.Signals, "execution_status"); status != ArvisExecutionNotApplicable {
		t.Fatalf("raydium status=%q arm=%#v", status, raydium)
	}
	if code := arvisSignalString(raydium.Signals, "reason_code"); code != "no_amm_pool" {
		t.Fatalf("raydium reason=%q", code)
	}
}

func TestArvisPumpAndRaydiumCanBothBuildForMigratedPoolEvidence(t *testing.T) {
	req := SecurityRadarRequest{Target: "MigratedMint111111111111111111111111111111pump", Network: "solana-mainnet", Mode: "owner_manual"}
	profile := radarEvidenceProfile{LiveRPC: true, AccountExists: true, AccountOwner: defaultRaydiumProgramID, RecentSignatureCount: 8, DataQuality: "live_rpc_evidence", EvidenceStatus: "verified_rpc_observation"}
	pump := buildPumpProgramApplicabilityArm(req, profile, "2026-07-18T00:00:00Z")
	raydium := buildRaydiumProgramApplicabilityArm(req, profile, "2026-07-18T00:00:00Z")
	if !pump.Signed || !raydium.Signed {
		t.Fatalf("expected both arms to build: pump=%#v raydium=%#v", pump, raydium)
	}
}

func TestArvisPumpAndRaydiumDistinctNotApplicableReasons(t *testing.T) {
	req := SecurityRadarRequest{Target: "PlainMint111111111111111111111111111111111", Network: "solana-mainnet", Mode: "owner_manual"}
	profile := radarEvidenceProfile{LiveRPC: true, AccountExists: true, AccountOwner: "TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA", RecentSignatureCount: 5, DataQuality: "live_rpc_evidence", EvidenceStatus: "verified_rpc_observation"}
	pump := buildPumpProgramApplicabilityArm(req, profile, "2026-07-18T00:00:00Z")
	raydium := buildRaydiumProgramApplicabilityArm(req, profile, "2026-07-18T00:00:00Z")
	if arvisSignalString(pump.Signals, "reason_code") != "no_pump_program_relation" {
		t.Fatalf("pump reason=%#v", pump.Signals)
	}
	if arvisSignalString(raydium.Signals, "reason_code") != "no_amm_pool" {
		t.Fatalf("raydium reason=%#v", raydium.Signals)
	}
}

func TestSecurityModuleAllowlistWithholdsDisabledArmEvidence(t *testing.T) {
	t.Setenv("KOSCHEI_SECURITY_MODULES", ModuleHolderConcentration)
	req := SecurityRadarRequest{Target: "target", Network: "solana-mainnet"}
	generatedAt := time.Now().UTC().Format(time.RFC3339)
	arms := []SecurityRadarVerdict{
		evidenceArm("Holder Concentration", ModuleHolderConcentration, req, 1, map[string]any{"real_onchain_evidence": true}, []string{"holder evidence"}, generatedAt),
		evidenceArm("Funding Cluster Detector", ModuleFundingClusterDetector, req, 1, map[string]any{"real_onchain_evidence": true}, []string{"funding evidence"}, generatedAt),
	}
	got := applyRuntimeSecurityModulePolicy(req, generatedAt, arms)
	if len(got) != 2 || !got[0].Signed || got[1].Signed {
		t.Fatalf("module allowlist did not preserve/withhold correctly: %#v", got)
	}
	if status := arvisSignalString(got[1].Signals, "execution_status"); status != ArvisExecutionSourceUnavailable {
		t.Fatalf("disabled module status=%q", status)
	}
}
