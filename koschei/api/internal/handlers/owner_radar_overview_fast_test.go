package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestWithoutPumpHighVolumeLegacyFinalsUsesExactSolanaTarget(t *testing.T) {
	items := []services.SecurityRadarVerdictRecord{
		{Target: "MintCaseSensitive", ModuleID: services.ModuleFinalVerdictEngine, Signed: true},
		{Target: "mintcasesensitive", ModuleID: services.ModuleFinalVerdictEngine, Signed: true},
		{Target: "OtherMint", ModuleID: services.ModuleFinalVerdictEngine, Signed: true},
	}
	pump := []services.PumpHighVolumeOwnerItem{{Target: "MintCaseSensitive", ReportStatus: "completed_unsigned"}}

	got := withoutPumpHighVolumeLegacyFinals(items, pump)
	if len(got) != 2 {
		t.Fatalf("filtered items=%#v", got)
	}
	if got[0].Target != "mintcasesensitive" || got[1].Target != "OtherMint" {
		t.Fatalf("Solana target filtering must be exact and case-sensitive: %#v", got)
	}
}
