package services

import "testing"

func TestSummarizeSecurityRadarContinuityCaughtUp(t *testing.T) {
	report := summarizeSecurityRadarContinuity([]SecurityRadarContinuitySource{
		{Network: "solana-mainnet", ProgramID: "pump", ModuleID: ModulePumpSybilRadar, Status: "caught_up", RecoveredEvents: 4},
		{Network: "solana-mainnet", ProgramID: "raydium", ModuleID: ModuleRaydiumPoolGuardian, Status: "caught_up", RecoveredEvents: 2},
	})
	if !report.Available || !report.AllCaughtUp || report.Status != "caught_up" {
		t.Fatalf("unexpected continuity report: %#v", report)
	}
	if report.RecoveredEvents != 6 {
		t.Fatalf("expected recovered event total 6, got %d", report.RecoveredEvents)
	}
}

func TestSummarizeSecurityRadarContinuityNeverHidesBlockedSource(t *testing.T) {
	report := summarizeSecurityRadarContinuity([]SecurityRadarContinuitySource{
		{ProgramID: "pump", Status: "caught_up"},
		{ProgramID: "raydium", Status: "blocked_history_boundary", LastError: "history boundary unavailable"},
	})
	if report.Status != "blocked" || report.BlockedCount != 1 || report.AllCaughtUp {
		t.Fatalf("blocked source was hidden: %#v", report)
	}
}

func TestSummarizeSecurityRadarContinuityRPCErrorBeatsRecovering(t *testing.T) {
	report := summarizeSecurityRadarContinuity([]SecurityRadarContinuitySource{
		{ProgramID: "pump", Status: "backfilling"},
		{ProgramID: "raydium", Status: "rpc_error"},
	})
	if report.Status != "degraded" || report.RPCErrorCount != 1 || report.RecoveringCount != 1 {
		t.Fatalf("unexpected degraded report: %#v", report)
	}
}
