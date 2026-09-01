package handlers

import (
	"testing"

	"koschei/api/internal/services"
)

func TestCanonicalPumpSelectiveSchedulingSurvivesBroadSaverGates(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("KOSCHEI_OWNER_UNLIMITED_AUTOSCAN_ENABLED", "false")
	t.Setenv("KOSCHEI_AUTOMATIC_SCANNING_ENABLED", "false")
	t.Setenv("SOLANA_RPC_LIMIT_SAVER_ENABLED", "true")
	t.Setenv("PUMPPORTAL_ENABLED", "true")
	t.Setenv("PUMP_HIGH_VOLUME_RADAR_ENABLED", "true")

	if services.AutomaticBackgroundScanningEnabled() {
		t.Fatal("broad automatic scanning must remain disabled")
	}
	if !services.SolanaRPCLimitSaverEnabled() {
		t.Fatal("RPC saver must remain enabled")
	}
	if !canonicalPumpAutoSchedulingAllowed() {
		t.Fatal("explicit selective Pump scheduling must remain available under broad saver gates")
	}
	if got := canonicalPumpMaxJobsPerCycle(); got != 1 {
		t.Fatalf("selective Pump job cap=%d want=1", got)
	}
}

func TestCanonicalPumpSelectiveSchedulingRequiresPumpGate(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("KOSCHEI_OWNER_UNLIMITED_AUTOSCAN_ENABLED", "false")
	t.Setenv("KOSCHEI_AUTOMATIC_SCANNING_ENABLED", "true")
	t.Setenv("SOLANA_RPC_LIMIT_SAVER_ENABLED", "false")
	t.Setenv("PUMPPORTAL_ENABLED", "true")
	t.Setenv("PUMP_HIGH_VOLUME_RADAR_ENABLED", "false")

	if canonicalPumpAutoSchedulingAllowed() {
		t.Fatal("selective Pump scheduling must fail closed when PUMP_HIGH_VOLUME_RADAR_ENABLED=false")
	}
}
