package runtimecfg

import "testing"

func TestLoadRestoresLegacyControlPlane(t *testing.T) {
	t.Setenv("APP_NAME", "Koschei X")
	t.Setenv("AI_ENABLED", "false")
	t.Setenv("AI_PROVIDER", "together")
	t.Setenv("FEATURE_LAUNCH_PAGE_BUILDER", "0")
	t.Setenv("FEATURE_RISK_SCANNER", "1")
	t.Setenv("FEATURE_SOLANA", "true")
	t.Setenv("KOSCHEI_MODEL_ROUTER_ENABLED", "false")
	t.Setenv("KOSCHEI_PUBLIC_BADGE_ENABLED", "false")
	t.Setenv("KOSCHEI_SECURITY_MODULES", "repeat_actor_scan, holder_concentration,repeat_actor_scan")
	t.Setenv("KOSCHEI_SECURITY_PROVIDER", "helius")
	t.Setenv("KOSCHEI_VERDICT_MODE", "observe")
	t.Setenv("SOLANA_NETWORK", "mainnet-beta")
	t.Setenv("SOLSCAN_API_KEY", "configured")
	t.Setenv("TOGETHER_AI_ENABLED", "false")
	t.Setenv("WEB3_PROVIDER", "quicknode")
	t.Setenv("WORKER_MAX_BUILD_THREADS", "7")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "guard-v1")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", "secret")
	t.Setenv("TRANSACTION_GUARD_ENFORCEMENT_PERMIT_TTL_SECONDS", "120")
	t.Setenv("TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", "true")
	t.Setenv("TRANSACTION_GUARD_STATE_RECHECK_COURT_RISK_THRESHOLD", "17")

	cfg := Load()
	if cfg.AppName != "Koschei X" || cfg.AIEnabled || cfg.AIProvider != "together" || cfg.LaunchPageBuilderEnabled || !cfg.RiskScannerEnabled || !cfg.SolanaEnabled {
		t.Fatalf("unexpected core config: %#v", cfg)
	}
	if cfg.ModelRouterEnabled || cfg.PublicBadgeEnabled || cfg.SecurityProvider != "helius" || cfg.VerdictMode != "observe" {
		t.Fatalf("unexpected security config: %#v", cfg)
	}
	if cfg.SolanaNetwork != "solana-mainnet" || !cfg.SolscanConfigured || cfg.TogetherEnabled || cfg.Web3Provider != "quicknode" || cfg.WorkerMaxBuildThreads != 7 {
		t.Fatalf("unexpected provider config: %#v", cfg)
	}
	if cfg.Guard.KeyID != "guard-v1" || !cfg.Guard.PrivateKeyConfigured || cfg.Guard.PermitTTL.Seconds() != 120 || !cfg.Guard.RequirePermit || cfg.Guard.StateRecheckCourtRiskThreshold != 17 {
		t.Fatalf("unexpected guard config: %#v", cfg.Guard)
	}
}

func TestGuardStateRecheckCourtRiskThresholdDefaultsOutsideCurrentAllowBand(t *testing.T) {
	cfg := LoadWith(func(string) string { return "" })
	if cfg.Guard.StateRecheckCourtRiskThreshold != 25 {
		t.Fatalf("threshold=%d want=25", cfg.Guard.StateRecheckCourtRiskThreshold)
	}
}

func TestGuardStateRecheckCourtRiskThresholdIsBounded(t *testing.T) {
	cfg := LoadWith(func(key string) string {
		if key == "TRANSACTION_GUARD_STATE_RECHECK_COURT_RISK_THRESHOLD" {
			return "999"
		}
		return ""
	})
	if cfg.Guard.StateRecheckCourtRiskThreshold != 100 {
		t.Fatalf("threshold=%d want=100", cfg.Guard.StateRecheckCourtRiskThreshold)
	}
}

func TestModuleEnabledAllowlist(t *testing.T) {
	t.Setenv("KOSCHEI_SECURITY_MODULES", "repeat_actor_scan,holder_concentration")
	if !ModuleEnabled("repeat_actor_scan") || !ModuleEnabled("holder_concentration") {
		t.Fatal("allowlisted module disabled")
	}
	if ModuleEnabled("funding_cluster_detector") {
		t.Fatal("non-allowlisted module enabled")
	}
}

func TestInvalidLegacyValuesPreserveSafeDefaults(t *testing.T) {
	t.Setenv("AI_PROVIDER", "mystery")
	t.Setenv("WEB3_PROVIDER", "mystery")
	t.Setenv("KOSCHEI_VERDICT_MODE", "mystery")
	t.Setenv("WORKER_MAX_BUILD_THREADS", "9999")
	t.Setenv("SOLANA_NETWORK", "mystery")
	cfg := Load()
	if cfg.AIProvider != "auto" || cfg.Web3Provider != "auto" || cfg.VerdictMode != DefaultSecurityMode || cfg.WorkerMaxBuildThreads != 64 || cfg.SolanaNetwork != DefaultSolanaNetwork {
		t.Fatalf("unsafe fallback: %#v", cfg)
	}
}
