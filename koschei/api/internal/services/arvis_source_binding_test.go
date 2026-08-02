package services

import (
	"testing"
	"time"
)

func TestArvisSourceModuleParsing(t *testing.T) {
	cases := []struct {
		mode string
		want string
	}{
		{mode: "live_stream:" + ModulePumpSybilRadar, want: ModulePumpSybilRadar},
		{mode: "live_stream:" + ModuleRaydiumPoolGuardian, want: ModuleRaydiumPoolGuardian},
		{mode: "manual_dashboard_check", want: ""},
		{mode: "polling", want: ""},
		{mode: "live_stream:unknown", want: ""},
	}
	for _, tc := range cases {
		if got := arvisSourceModule(tc.mode); got != tc.want {
			t.Fatalf("arvisSourceModule(%q)=%q want=%q", tc.mode, got, tc.want)
		}
	}
}

func TestArvisStreamAnalysisMode(t *testing.T) {
	if got := arvisStreamAnalysisMode(ModulePumpSybilRadar); got != "live_stream:"+ModulePumpSybilRadar {
		t.Fatalf("unexpected Pump stream mode: %s", got)
	}
	if got := arvisStreamAnalysisMode(ModuleRaydiumPoolGuardian); got != "live_stream:"+ModuleRaydiumPoolGuardian {
		t.Fatalf("unexpected Raydium stream mode: %s", got)
	}
	if got := arvisStreamAnalysisMode("unknown"); got != "live_stream" {
		t.Fatalf("unexpected unknown stream mode: %s", got)
	}
}

func TestPumpAndRaydiumTransactionArmsStaySourceSpecific(t *testing.T) {
	generatedAt := time.Now().UTC().Format(time.RFC3339)
	pumpReq := SecurityRadarRequest{Target: "pump-target", Network: "solana-mainnet", Mode: "live_stream:" + ModulePumpSybilRadar}
	raydiumReq := SecurityRadarRequest{Target: "raydium-target", Network: "solana-mainnet", Mode: "live_stream:" + ModuleRaydiumPoolGuardian}

	pumpEvidence := arvisTransactionEvidence{
		Available:           true,
		PumpRelated:         true,
		Signers:             []string{"creator"},
		FundingAccounts:     []string{"funder"},
		ProgramIDs:          []string{defaultPumpProgramID},
		TokenBalanceChanges: map[string]float64{},
		LamportDeltas:       map[string]int64{},
	}
	pumpArm := buildPumpTransactionArm(pumpReq, pumpEvidence, generatedAt)
	if !pumpArm.Signed || !SecurityRadarVerdictHasVerifiedEvidence(pumpArm) {
		t.Fatalf("Pump evidence did not produce verified Pump arm: %#v", pumpArm)
	}
	if raydiumArm := buildRaydiumTransactionArm(pumpReq, pumpEvidence, generatedAt); raydiumArm.Signed {
		t.Fatalf("Pump evidence incorrectly signed Raydium arm: %#v", raydiumArm)
	}

	raydiumEvidence := arvisTransactionEvidence{
		Available:           true,
		RaydiumRelated:      true,
		ProgramIDs:          []string{"675kPX9MHTjS2zt1qfr1NYhd1B9M9QGK6cEcDDCo2t9"},
		TokenMints:          []string{"mint-a", "mint-b"},
		TokenBalanceChanges: map[string]float64{"mint-a": -10, "mint-b": 10},
		LamportDeltas:       map[string]int64{},
	}
	raydiumArm := buildRaydiumTransactionArm(raydiumReq, raydiumEvidence, generatedAt)
	if !raydiumArm.Signed || !SecurityRadarVerdictHasVerifiedEvidence(raydiumArm) {
		t.Fatalf("Raydium evidence did not produce verified Raydium arm: %#v", raydiumArm)
	}
	if pumpArm := buildPumpTransactionArm(raydiumReq, raydiumEvidence, generatedAt); pumpArm.Signed {
		t.Fatalf("Raydium evidence incorrectly signed Pump arm: %#v", pumpArm)
	}
}
