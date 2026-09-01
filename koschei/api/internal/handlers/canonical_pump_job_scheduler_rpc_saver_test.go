package handlers

import "testing"

func TestCanonicalPumpAutoSchedulingAllowedBySelectiveGateUnderRPCLimitSaver(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("KOSCHEI_OWNER_UNLIMITED_AUTOSCAN_ENABLED", "false")
	t.Setenv("SOLANA_RPC_LIMIT_SAVER_ENABLED", "true")
	t.Setenv("PUMPPORTAL_ENABLED", "true")
	t.Setenv("PUMP_HIGH_VOLUME_RADAR_ENABLED", "true")
	if !canonicalPumpAutoSchedulingAllowed() {
		t.Fatal("explicit selective Pump scheduling must remain allowed while broad RPC saver is active")
	}
}

func TestCanonicalPumpAutoSchedulingStillRequiresSelectiveGateWhenSaverDisabled(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("KOSCHEI_OWNER_UNLIMITED_AUTOSCAN_ENABLED", "false")
	t.Setenv("SOLANA_RPC_LIMIT_SAVER_ENABLED", "false")
	t.Setenv("PUMPPORTAL_ENABLED", "true")
	t.Setenv("PUMP_HIGH_VOLUME_RADAR_ENABLED", "false")
	if canonicalPumpAutoSchedulingAllowed() {
		t.Fatal("disabling RPC saver must not implicitly enable selective Pump scheduling")
	}
}

func TestCanonicalPumpOwnerUnlimitedDoesNotBypassDisabledSelectiveGate(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("KOSCHEI_OWNER_UNLIMITED_AUTOSCAN_ENABLED", "true")
	t.Setenv("SOLANA_RPC_LIMIT_SAVER_ENABLED", "true")
	t.Setenv("PUMPPORTAL_ENABLED", "true")
	t.Setenv("PUMP_HIGH_VOLUME_RADAR_ENABLED", "false")
	if canonicalPumpAutoSchedulingAllowed() {
		t.Fatal("owner unlimited mode must not silently enable a selectively disabled Pump scheduler")
	}
}
