package handlers

import (
	"context"
	"testing"
	"time"

	"koschei/api/internal/services"
)

func TestApplyMarketProgramEvidenceReferences(t *testing.T) {
	core := holderIntelligenceCoreResult{
		ExitLiquidity: services.ExitLiquiditySimulation{
			Available:  true,
			Mint:       "Mint111111111111111111111111111111111111111",
			OutputMint: "USDC111111111111111111111111111111111111111",
			Tiers: []services.ExitLiquidityTier{
				{RequestedNotionalUSD: 1000, Available: true, Status: "quoted", QuoteContextSlot: 101},
				{RequestedNotionalUSD: 10000, Available: true, Status: "quoted", QuoteContextSlot: 202},
				{RequestedNotionalUSD: 100000, Available: false, Status: "quote_unavailable"},
			},
		},
		SourceContext: map[string]any{
			"program_security": services.ProgramSecuritySurface{
				Available: true,
				Status:    "complete",
				Programs: []services.ProgramSecurityEvidence{
					{
						Available: true, Role: "launch_program",
						ProgramID:          "Program11111111111111111111111111111111111",
						ProgramDataAddress: "ProgramData1111111111111111111111111111111",
						LoaderID:           "Loader111111111111111111111111111111111111",
						UpgradeAuthority:   "Authority111111111111111111111111111111111",
						AccountSlot:        303, DeploymentSlot: 404,
						EvidenceRefs: []string{"rpc:getAccountInfo", "rpc:getBlockTime"},
					},
				},
			},
		},
	}
	refs := applyMarketProgramEvidenceReferences(map[string]unifiedEvidenceReference{}, core)
	liquidity := refs["liquidity"]
	if len(liquidity.Slots) != 2 || liquidity.Slots[0] != 101 || liquidity.Slots[1] != 202 {
		t.Fatalf("unexpected exit quote slots: %+v", liquidity.Slots)
	}
	if len(liquidity.EvidenceKeys) != 2 {
		t.Fatalf("unexpected exit quote evidence keys: %+v", liquidity.EvidenceKeys)
	}
	program := refs["program"]
	if len(program.Wallets) != 1 || program.Wallets[0] != "Authority111111111111111111111111111111111" {
		t.Fatalf("upgrade authority reference missing: %+v", program)
	}
	if len(program.Slots) != 2 || program.Slots[0] != 303 || program.Slots[1] != 404 {
		t.Fatalf("program slots missing: %+v", program.Slots)
	}
}

func TestUnifiedReportPublishesExitAndProgramSecurityTopLevel(t *testing.T) {
	program := services.ProgramSecuritySurface{
		Available: true,
		Status:    "complete",
		Programs: []services.ProgramSecurityEvidence{
			{Available: true, Role: "launch_program", ProgramID: "Program11111111111111111111111111111111111", Immutable: true},
		},
		ObservedAt: time.Now().UTC(),
	}
	exit := services.ExitLiquiditySimulation{
		Available: true,
		Status:    "complete",
		Provider:  "jupiter_quote",
		Mint:      "Mint111111111111111111111111111111111111111",
		QuoteOnly: true,
		Tiers: []services.ExitLiquidityTier{
			{RequestedNotionalUSD: 1000, Available: true, Status: "quoted", EstimatedProceedsUSD: 975, ExecutionShortfallPct: 2.5, QuoteContextSlot: 55},
		},
		ObservedAt: time.Now().UTC(),
	}
	core := holderIntelligenceCoreResult{
		Request:       services.SecurityRadarRequest{Target: exit.Mint, Network: "solana-mainnet", Mode: "stored_only_projection"},
		ExitLiquidity: exit,
		SourceContext: map[string]any{"program_security": program},
		Cluster:       services.HolderClusterAnalysis{Findings: []string{}},
	}
	assembly := (&Handler{}).assembleUnifiedInvestigationReport(context.Background(), core)
	gotExit, ok := assembly.Report["exit_liquidity"].(services.ExitLiquiditySimulation)
	if !ok || !gotExit.Available || !gotExit.QuoteOnly {
		t.Fatalf("top-level exit liquidity missing: %#v", assembly.Report["exit_liquidity"])
	}
	gotProgram, ok := assembly.Report["program_security"].(services.ProgramSecuritySurface)
	if !ok || !gotProgram.Available || len(gotProgram.Programs) != 1 {
		t.Fatalf("top-level program security missing: %#v", assembly.Report["program_security"])
	}
	refs, ok := assembly.Report["evidence_references"].(map[string]unifiedEvidenceReference)
	if !ok {
		t.Fatalf("evidence references missing: %#v", assembly.Report["evidence_references"])
	}
	if !unifiedEvidenceReferencePresent(refs["liquidity"]) || !unifiedEvidenceReferencePresent(refs["program"]) {
		t.Fatalf("market/program references missing: %+v", refs)
	}
}
