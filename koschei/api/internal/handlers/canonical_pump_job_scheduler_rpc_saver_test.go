package handlers

import "testing"

func TestCanonicalPumpAutoSchedulingBlockedByRPCLimitSaver(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("KOSCHEI_OWNER_UNLIMITED_AUTOSCAN_ENABLED", "false")
	t.Setenv("SOLANA_RPC_LIMIT_SAVER_ENABLED", "true")
	if canonicalPumpAutoSchedulingAllowed() {
		t.Fatal("automatic pump scheduling must be blocked while RPC limit saver is active")
	}
}

func TestCanonicalPumpAutoSchedulingAllowedWhenSaverDisabled(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("KOSCHEI_OWNER_UNLIMITED_AUTOSCAN_ENABLED", "false")
	t.Setenv("SOLANA_RPC_LIMIT_SAVER_ENABLED", "false")
	if !canonicalPumpAutoSchedulingAllowed() {
		t.Fatal("automatic pump scheduling should be allowed when RPC limit saver is explicitly disabled")
	}
}

func TestCanonicalPumpOwnerUnlimitedModeOverridesLimitSaver(t *testing.T) {
	t.Setenv("APP_ENV", "production")
	t.Setenv("KOSCHEI_OWNER_UNLIMITED_AUTOSCAN_ENABLED", "true")
	t.Setenv("SOLANA_RPC_LIMIT_SAVER_ENABLED", "true")
	if !canonicalPumpAutoSchedulingAllowed() {
		t.Fatal("owner unlimited autoscan mode should explicitly allow automatic pump scheduling")
	}
}
