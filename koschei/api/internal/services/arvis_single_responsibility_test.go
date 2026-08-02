package services

import "testing"

func TestArvisArchitectureHasFourteenEvidenceOnlyArms(t *testing.T) {
	t.Setenv("SOLANA_RPC_URL", "")
	analysis := AnalyzeArvisRadars(SecurityRadarRequest{Target: "Mint11111111111111111111111111111111111111", Network: "solana-mainnet", Mode: "manual_test"})
	if len(analysis.Arms) != 14 {
		t.Fatalf("arm count=%d", len(analysis.Arms))
	}
	seen := map[string]bool{}
	for _, arm := range analysis.Arms {
		if arm.ModuleID == ModuleIntelligenceGraph || arm.ModuleID == ModuleFinalVerdictEngine {
			t.Fatalf("presentation/final layer leaked into evidence arms: %s", arm.ModuleID)
		}
		if seen[arm.ModuleID] {
			t.Fatalf("duplicate arm %s", arm.ModuleID)
		}
		seen[arm.ModuleID] = true
		if arm.Grade != "-" || arm.RiskIndex != 0 {
			t.Fatalf("arm %s issued grade=%q risk=%d", arm.ModuleID, arm.Grade, arm.RiskIndex)
		}
	}
	for _, required := range []string{ModuleLaunchDistribution, ModuleRepeatActorScan, ModuleCreatorLinkAnalysis, ModuleLiquidityMovement} {
		if !seen[required] {
			t.Fatalf("missing arm %s", required)
		}
	}
	if analysis.Final.Grade != "-" || analysis.Final.Signed {
		t.Fatalf("compatibility final=%#v", analysis.Final)
	}
}

func TestLargestHolderFactBelongsOnlyToHolderArm(t *testing.T) {
	req := SecurityRadarRequest{Target: "Mint22222222222222222222222222222222222222", Network: "solana-mainnet", Mode: "manual_test"}
	profile := radarEvidenceProfile{
		LiveRPC: true, AccountExists: true, IsTokenMint: true,
		AccountOwner:    "TokenProgram111111111111111111111111111111",
		LargestAccounts: 20, LargestHolderPct: 61, Top10HolderPct: 88,
		RawLargestHolderPct: 61, RawTop10HolderPct: 88, TokenSupply: 1000000,
		DataQuality: "live_rpc_evidence", EvidenceStatus: "verified_rpc_observation",
		HolderRoles: HolderRoleAnalysis{Available: true},
	}
	holder := buildHolderArm(req, profile, "2026-07-15T00:00:00Z")
	graph := buildIntelligenceGraphArm(req, profile, "2026-07-15T00:00:00Z")
	if _, ok := holder.Signals["largest_holder_percentage"]; !ok {
		t.Fatal("holder arm missing largest-holder fact")
	}
	for _, key := range []string{"largest_holder_percentage", "top_10_holder_percentage", "raw_largest_holder_percentage", "raw_top_10_holder_percentage"} {
		if _, ok := graph.Signals[key]; ok {
			t.Fatalf("graph recalculated holder fact %s", key)
		}
	}
	if graph.RiskIndex != 0 || graph.Grade != "-" {
		t.Fatalf("graph issued score/grade: %#v", graph)
	}
}

func TestCreatorAndLiquidityReplaceUnavailablePlaceholders(t *testing.T) {
	req := SecurityRadarRequest{Target: "Mint33333333333333333333333333333333333333", Network: "solana-mainnet", Mode: "manual_test"}
	analysis := AnalyzeArvisRadars(req)
	market := TokenMarketSnapshot{
		Available: true, Provider: "test", Mint: req.Target,
		LiquidityUSD: 125000, BestPairAddress: "Pair111111111111111111111111111111111111",
		BestPairDEX: "raydium", BestPairLiquidityUSD: 125000, PairCount: 1,
	}
	analysis = ApplyCreatorAndLiquidityEvidenceToAnalysis(analysis, req, "Creator111111111111111111111111111111111", market, LaunchForensicsAnalysis{})
	creatorFound := false
	liquidityFound := false
	for _, arm := range analysis.Arms {
		switch arm.ModuleID {
		case ModuleCreatorLinkAnalysis:
			creatorFound = arm.Signed && arm.Signals["creator_wallet"] != nil
		case ModuleLiquidityMovement:
			liquidityFound = arm.Signed && arm.Signals["liquidity_usd"] != nil
		}
		if arm.RiskIndex != 0 || arm.Grade != "-" {
			t.Fatalf("extension arm issued score/grade: %s %#v", arm.ModuleID, arm)
		}
	}
	if !creatorFound || !liquidityFound {
		t.Fatalf("creator=%t liquidity=%t", creatorFound, liquidityFound)
	}
}
