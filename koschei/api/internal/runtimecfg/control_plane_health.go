package runtimecfg

import (
	"os"
	"strconv"
	"strings"
)

const (
	ControlStateActive        = "active"
	ControlStateDisabled      = "disabled"
	ControlStateDefaulted     = "defaulted"
	ControlStateShadowed      = "shadowed"
	ControlStateMisconfigured = "misconfigured"
)

var recoveredControlPlaneEnvNames = []string{
	"AI_ENABLED",
	"AI_PROVIDER",
	"APP_NAME",
	"FEATURE_LAUNCH_PAGE_BUILDER",
	"FEATURE_RISK_SCANNER",
	"FEATURE_SOLANA",
	"KOSCHEI_MODEL_ROUTER_ENABLED",
	"KOSCHEI_PUBLIC_BADGE_ENABLED",
	"KOSCHEI_SECURITY_MODULES",
	"KOSCHEI_SECURITY_PROVIDER",
	"KOSCHEI_VERDICT_MODE",
	"SOLANA_NETWORK",
	"SOLSCAN_API_KEY",
	"TOGETHER_AI_ENABLED",
	"WEB3_PROVIDER",
	"WORKER_MAX_BUILD_THREADS",
	"TRANSACTION_GUARD_ENFORCEMENT_KEY_ID",
	"TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY",
	"TRANSACTION_GUARD_ENFORCEMENT_PERMIT_TTL_SECONDS",
	"TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT",
}

type ControlPlaneItem struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail,omitempty"`
	Secret bool   `json:"secret,omitempty"`
}

type ControlPlaneHealth struct {
	Version       string             `json:"version"`
	OK            bool               `json:"ok"`
	Controls      int                `json:"controls"`
	Active        int                `json:"active"`
	Disabled      int                `json:"disabled"`
	Defaulted     int                `json:"defaulted"`
	Shadowed      int                `json:"shadowed"`
	Misconfigured int                `json:"misconfigured"`
	Items         []ControlPlaneItem `json:"items"`
}

func RecoveredControlPlaneEnvNames() []string {
	return append([]string(nil), recoveredControlPlaneEnvNames...)
}

func ControlPlaneHealthSnapshot() ControlPlaneHealth {
	return ControlPlaneHealthWith(os.Getenv)
}

func ControlPlaneHealthWith(get Getter) ControlPlaneHealth {
	if get == nil {
		get = os.Getenv
	}

	cfg := LoadWith(get)
	items := []ControlPlaneItem{
		boolControl(get, "AI_ENABLED", true),
		enumControl(get, "AI_PROVIDER", "auto", "auto", "together"),
		stringControl(get, "APP_NAME", DefaultAppName, false),
		boolControl(get, "FEATURE_LAUNCH_PAGE_BUILDER", true),
		boolControl(get, "FEATURE_RISK_SCANNER", true),
		boolControl(get, "FEATURE_SOLANA", true),
		boolControl(get, "KOSCHEI_MODEL_ROUTER_ENABLED", true),
		boolControl(get, "KOSCHEI_PUBLIC_BADGE_ENABLED", true),
		csvControl(get, "KOSCHEI_SECURITY_MODULES"),
		enumControl(get, "KOSCHEI_SECURITY_PROVIDER", DefaultSecuritySource, "auto", "alchemy", "helius", "quicknode", "rpc", "solscan"),
		enumControl(get, "KOSCHEI_VERDICT_MODE", DefaultSecurityMode, "evidence_first", "strict", "observe", "evidence_only"),
		networkControl(get, "SOLANA_NETWORK"),
		secretControl(get, "SOLSCAN_API_KEY", false),
		boolControl(get, "TOGETHER_AI_ENABLED", true),
		enumControl(get, "WEB3_PROVIDER", DefaultWeb3Provider, "auto", "alchemy", "helius", "quicknode", "rpc", "solscan"),
		boundedIntControl(get, "WORKER_MAX_BUILD_THREADS", 2, 1, 64),
		stringControl(get, "TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", "", false),
		secretControl(get, "TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", false),
		boundedIntControl(get, "TRANSACTION_GUARD_ENFORCEMENT_PERMIT_TTL_SECONDS", 90, 10, 600),
		boolControl(get, "TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", false),
	}

	applyAIShadowing(items, cfg, get)
	applyGuardDependencies(items, cfg)

	report := ControlPlaneHealth{
		Version:  "runtime-control-plane/v1",
		Controls: len(items),
		Items:    items,
	}
	for _, item := range items {
		switch item.State {
		case ControlStateActive:
			report.Active++
		case ControlStateDisabled:
			report.Disabled++
		case ControlStateDefaulted:
			report.Defaulted++
		case ControlStateShadowed:
			report.Shadowed++
		case ControlStateMisconfigured:
			report.Misconfigured++
		}
	}
	report.OK = report.Misconfigured == 0
	return report
}

func stringControl(get Getter, name, fallback string, secret bool) ControlPlaneItem {
	raw := strings.TrimSpace(get(name))
	if raw == "" {
		return ControlPlaneItem{Name: name, State: ControlStateDefaulted, Detail: "runtime default in effect", Secret: secret}
	}
	return ControlPlaneItem{Name: name, State: ControlStateActive, Detail: "explicit runtime value in effect", Secret: secret}
}

func secretControl(get Getter, name string, required bool) ControlPlaneItem {
	raw := strings.TrimSpace(get(name))
	if raw == "" {
		state := ControlStateDefaulted
		detail := "optional credential not configured"
		if required {
			state = ControlStateMisconfigured
			detail = "required credential is missing"
		}
		return ControlPlaneItem{Name: name, State: state, Detail: detail, Secret: true}
	}
	return ControlPlaneItem{Name: name, State: ControlStateActive, Detail: "credential configured", Secret: true}
}

func boolControl(get Getter, name string, fallback bool) ControlPlaneItem {
	raw := strings.ToLower(strings.TrimSpace(get(name)))
	if raw == "" {
		state := ControlStateDefaulted
		detail := "runtime default enabled"
		if !fallback {
			detail = "runtime default disabled"
		}
		return ControlPlaneItem{Name: name, State: state, Detail: detail}
	}
	value, ok := parseBoolControl(raw)
	if !ok {
		return ControlPlaneItem{Name: name, State: ControlStateMisconfigured, Detail: "invalid boolean value; safe runtime default is being used"}
	}
	if !value {
		return ControlPlaneItem{Name: name, State: ControlStateDisabled, Detail: "explicitly disabled"}
	}
	return ControlPlaneItem{Name: name, State: ControlStateActive, Detail: "explicitly enabled"}
}

func parseBoolControl(raw string) (bool, bool) {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "on", "enabled":
		return true, true
	case "0", "false", "no", "off", "disabled":
		return false, true
	default:
		return false, false
	}
}

func enumControl(get Getter, name, fallback string, allowed ...string) ControlPlaneItem {
	raw := strings.ToLower(strings.TrimSpace(get(name)))
	if raw == "" {
		return ControlPlaneItem{Name: name, State: ControlStateDefaulted, Detail: "runtime default " + fallback + " in effect"}
	}
	for _, item := range allowed {
		if raw == item {
			return ControlPlaneItem{Name: name, State: ControlStateActive, Detail: "explicit selector in effect"}
		}
	}
	return ControlPlaneItem{Name: name, State: ControlStateMisconfigured, Detail: "invalid selector; safe runtime default is being used"}
}

func csvControl(get Getter, name string) ControlPlaneItem {
	raw := strings.TrimSpace(get(name))
	if raw == "" {
		return ControlPlaneItem{Name: name, State: ControlStateDefaulted, Detail: "all registered modules enabled by default"}
	}
	parts := strings.Split(raw, ",")
	seen := 0
	for _, part := range parts {
		if strings.TrimSpace(part) != "" {
			seen++
		}
	}
	if seen == 0 {
		return ControlPlaneItem{Name: name, State: ControlStateMisconfigured, Detail: "module allowlist contains no usable module ids"}
	}
	return ControlPlaneItem{Name: name, State: ControlStateActive, Detail: "explicit module allowlist in effect"}
}

func boundedIntControl(get Getter, name string, fallback, minimum, maximum int) ControlPlaneItem {
	raw := strings.TrimSpace(get(name))
	if raw == "" {
		return ControlPlaneItem{Name: name, State: ControlStateDefaulted, Detail: "runtime default in effect"}
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return ControlPlaneItem{Name: name, State: ControlStateMisconfigured, Detail: "invalid integer; safe runtime default is being used"}
	}
	if value < minimum || value > maximum {
		return ControlPlaneItem{Name: name, State: ControlStateMisconfigured, Detail: "value is outside runtime bounds and will be clamped"}
	}
	return ControlPlaneItem{Name: name, State: ControlStateActive, Detail: "explicit bounded value in effect"}
}

func networkControl(get Getter, name string) ControlPlaneItem {
	raw := strings.ToLower(strings.TrimSpace(get(name)))
	if raw == "" {
		return ControlPlaneItem{Name: name, State: ControlStateDefaulted, Detail: "solana-mainnet runtime default in effect"}
	}
	switch raw {
	case "devnet", "solana-devnet", "testnet", "solana-testnet", "mainnet", "mainnet-beta", "solana-mainnet", "solana-mainnet-beta":
		return ControlPlaneItem{Name: name, State: ControlStateActive, Detail: "explicit Solana network selector in effect"}
	default:
		return ControlPlaneItem{Name: name, State: ControlStateMisconfigured, Detail: "invalid Solana network; mainnet safe default is being used"}
	}
}

func applyAIShadowing(items []ControlPlaneItem, cfg Config, get Getter) {
	if !cfg.AIEnabled || !cfg.ModelRouterEnabled {
		shadowIfExplicit(items, get, "AI_PROVIDER", "upstream AI/model-router gate disables provider selection")
		shadowIfExplicit(items, get, "TOGETHER_AI_ENABLED", "upstream AI/model-router gate disables Together routing")
		return
	}
	if cfg.AIProvider == "together" && !cfg.TogetherEnabled {
		setControlState(items, "AI_PROVIDER", ControlStateShadowed, "selected Together provider is explicitly disabled")
		return
	}
	if cfg.TogetherEnabled && (cfg.AIProvider == "auto" || cfg.AIProvider == "together") && strings.TrimSpace(get("TOGETHER_API_KEY")) == "" {
		setControlState(items, "AI_PROVIDER", ControlStateMisconfigured, "Together routing is enabled but TOGETHER_API_KEY is missing")
	}
}

func applyGuardDependencies(items []ControlPlaneItem, cfg Config) {
	if !cfg.Guard.RequirePermit {
		return
	}
	if strings.TrimSpace(cfg.Guard.KeyID) == "" {
		setControlState(items, "TRANSACTION_GUARD_ENFORCEMENT_KEY_ID", ControlStateMisconfigured, "required enforcement permit has no key id")
		setControlState(items, "TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", ControlStateMisconfigured, "required enforcement permit signer is incomplete")
	}
	if !cfg.Guard.PrivateKeyConfigured {
		setControlState(items, "TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", ControlStateMisconfigured, "required enforcement permit has no private key")
		setControlState(items, "TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT", ControlStateMisconfigured, "required enforcement permit signer is incomplete")
	}
}

func shadowIfExplicit(items []ControlPlaneItem, get Getter, name, detail string) {
	if strings.TrimSpace(get(name)) == "" {
		return
	}
	if item := findControl(items, name); item != nil && item.State != ControlStateMisconfigured {
		item.State = ControlStateShadowed
		item.Detail = detail
	}
}

func setControlState(items []ControlPlaneItem, name, state, detail string) {
	if item := findControl(items, name); item != nil {
		if item.State == ControlStateMisconfigured && state != ControlStateMisconfigured {
			return
		}
		item.State = state
		item.Detail = detail
	}
}

func findControl(items []ControlPlaneItem, name string) *ControlPlaneItem {
	for index := range items {
		if items[index].Name == name {
			return &items[index]
		}
	}
	return nil
}
