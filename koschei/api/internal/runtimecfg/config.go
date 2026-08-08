package runtimecfg

import (
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	DefaultAppName        = "Koschei Web3 Hub"
	DefaultSecurityMode   = "evidence_first"
	DefaultSecuritySource = "auto"
	DefaultWeb3Provider   = "auto"
	DefaultSolanaNetwork  = "solana-mainnet"
)

type Config struct {
	AppName                  string
	AIEnabled                bool
	AIProvider               string
	LaunchPageBuilderEnabled bool
	RiskScannerEnabled       bool
	SolanaEnabled            bool
	ModelRouterEnabled       bool
	PublicBadgeEnabled       bool
	SecurityModules          []string
	SecurityProvider         string
	VerdictMode              string
	SolanaNetwork            string
	SolscanConfigured        bool
	TogetherEnabled          bool
	Web3Provider             string
	WorkerMaxBuildThreads    int
	Guard                    GuardConfig
}

type GuardConfig struct {
	KeyID                string
	PrivateKeyConfigured bool
	PermitTTL            time.Duration
	RequirePermit        bool
}

type Getter func(string) string

func Load() Config { return LoadWith(os.Getenv) }

func LoadWith(get Getter) Config {
	if get == nil {
		get = os.Getenv
	}
	return Config{
		AppName:                  stringEnv(get, "APP_NAME", DefaultAppName),
		AIEnabled:                boolEnv(get, "AI_ENABLED", true),
		AIProvider:               enumEnv(get, "AI_PROVIDER", "auto", "auto", "together"),
		LaunchPageBuilderEnabled: boolEnv(get, "FEATURE_LAUNCH_PAGE_BUILDER", true),
		RiskScannerEnabled:       boolEnv(get, "FEATURE_RISK_SCANNER", true),
		SolanaEnabled:            boolEnv(get, "FEATURE_SOLANA", true),
		ModelRouterEnabled:       boolEnv(get, "KOSCHEI_MODEL_ROUTER_ENABLED", true),
		PublicBadgeEnabled:       boolEnv(get, "KOSCHEI_PUBLIC_BADGE_ENABLED", true),
		SecurityModules:          csvEnv(get, "KOSCHEI_SECURITY_MODULES"),
		SecurityProvider:         enumEnv(get, "KOSCHEI_SECURITY_PROVIDER", DefaultSecuritySource, "auto", "alchemy", "helius", "rpc", "solscan"),
		VerdictMode:              enumEnv(get, "KOSCHEI_VERDICT_MODE", DefaultSecurityMode, "evidence_first", "strict", "observe", "evidence_only"),
		SolanaNetwork:            normalizeSolanaNetwork(get("SOLANA_NETWORK")),
		SolscanConfigured:        strings.TrimSpace(get("SOLSCAN_API_KEY")) != "",
		TogetherEnabled:          boolEnv(get, "TOGETHER_AI_ENABLED", true),
		Web3Provider:             enumEnv(get, "WEB3_PROVIDER", DefaultWeb3Provider, "auto", "alchemy", "helius", "quicknode", "rpc", "solscan"),
		WorkerMaxBuildThreads:    intEnv(get, "WORKER_MAX_BUILD_THREADS", 2, 1, 64),
		Guard: GuardConfig{
			KeyID:                stringEnv(get, "TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", ""),
			PrivateKeyConfigured: strings.TrimSpace(get("TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY")) != "",
			PermitTTL:            durationSecondsEnv(get, "TRANSACTION_GUARD_ENFORCEMENT_PERMIT_TTL_SECONDS", 90, 10, 600),
			RequirePermit:        boolEnv(get, "TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", false),
		},
	}
}

func ModuleEnabled(moduleID string) bool {
	cfg := Load()
	if len(cfg.SecurityModules) == 0 {
		return true
	}
	moduleID = strings.ToLower(strings.TrimSpace(moduleID))
	for _, allowed := range cfg.SecurityModules {
		if allowed == "*" || allowed == "all" || allowed == moduleID {
			return true
		}
	}
	return false
}

func AIProviderAvailable(provider string) bool {
	cfg := Load()
	if !cfg.AIEnabled || !cfg.ModelRouterEnabled {
		return false
	}
	provider = strings.ToLower(strings.TrimSpace(provider))
	switch provider {
	case "together":
		return cfg.TogetherEnabled && strings.TrimSpace(os.Getenv("TOGETHER_API_KEY")) != ""
	default:
		return false
	}
}

func PublicSnapshot() map[string]any {
	cfg := Load()
	modules := append([]string{}, cfg.SecurityModules...)
	if len(modules) == 0 {
		modules = []string{"all"}
	}
	return map[string]any{
		"app_name": cfg.AppName,
		"ai": map[string]any{
			"enabled":              cfg.AIEnabled,
			"provider":             cfg.AIProvider,
			"model_router_enabled": cfg.ModelRouterEnabled,
			"together_enabled":     cfg.TogetherEnabled,
		},
		"features": map[string]any{
			"launch_page_builder": cfg.LaunchPageBuilderEnabled,
			"risk_scanner":        cfg.RiskScannerEnabled,
			"solana":              cfg.SolanaEnabled,
			"public_badge":        cfg.PublicBadgeEnabled,
		},
		"security": map[string]any{
			"modules":      modules,
			"provider":     cfg.SecurityProvider,
			"verdict_mode": cfg.VerdictMode,
		},
		"web3": map[string]any{
			"network":            cfg.SolanaNetwork,
			"provider":           cfg.Web3Provider,
			"solscan_configured": cfg.SolscanConfigured,
		},
		"worker": map[string]any{
			"max_build_threads": cfg.WorkerMaxBuildThreads,
		},
		"transaction_guard": map[string]any{
			"enforcement_key_id":          cfg.Guard.KeyID,
			"enforcement_key_configured":  cfg.Guard.PrivateKeyConfigured,
			"enforcement_permit_ttl_secs": int(cfg.Guard.PermitTTL / time.Second),
			"require_enforcement_permit":  cfg.Guard.RequirePermit,
		},
	}
}

func stringEnv(get Getter, name, fallback string) string {
	if value := strings.TrimSpace(get(name)); value != "" {
		return value
	}
	return fallback
}

func boolEnv(get Getter, name string, fallback bool) bool {
	raw := strings.ToLower(strings.TrimSpace(get(name)))
	if raw == "" {
		return fallback
	}
	switch raw {
	case "1", "true", "yes", "on", "enabled":
		return true
	case "0", "false", "no", "off", "disabled":
		return false
	default:
		return fallback
	}
}

func enumEnv(get Getter, name, fallback string, allowed ...string) string {
	raw := strings.ToLower(strings.TrimSpace(get(name)))
	if raw == "" {
		return fallback
	}
	for _, item := range allowed {
		if raw == item {
			return raw
		}
	}
	return fallback
}

func csvEnv(get Getter, name string) []string {
	raw := strings.TrimSpace(get(name))
	if raw == "" {
		return nil
	}
	seen := map[string]struct{}{}
	out := []string{}
	for _, item := range strings.Split(raw, ",") {
		item = strings.ToLower(strings.TrimSpace(item))
		if item == "" {
			continue
		}
		if _, ok := seen[item]; ok {
			continue
		}
		seen[item] = struct{}{}
		out = append(out, item)
	}
	sort.Strings(out)
	return out
}

func intEnv(get Getter, name string, fallback, minimum, maximum int) int {
	value := fallback
	if raw := strings.TrimSpace(get(name)); raw != "" {
		if parsed, err := strconv.Atoi(raw); err == nil {
			value = parsed
		}
	}
	if value < minimum {
		value = minimum
	}
	if value > maximum {
		value = maximum
	}
	return value
}

func durationSecondsEnv(get Getter, name string, fallback, minimum, maximum int) time.Duration {
	return time.Duration(intEnv(get, name, fallback, minimum, maximum)) * time.Second
}

func normalizeSolanaNetwork(raw string) string {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "devnet", "solana-devnet":
		return "solana-devnet"
	case "testnet", "solana-testnet":
		return "solana-testnet"
	case "mainnet", "mainnet-beta", "solana-mainnet", "solana-mainnet-beta", "":
		return DefaultSolanaNetwork
	default:
		return DefaultSolanaNetwork
	}
}
