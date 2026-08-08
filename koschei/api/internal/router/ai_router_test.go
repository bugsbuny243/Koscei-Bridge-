package router

import "testing"

func TestProviderFromEnvUsesTogetherOnly(t *testing.T) {
	oldGetEnv := getEnv
	defer func() { getEnv = oldGetEnv }()
	getEnv = func(key string) string {
		if key == "TOGETHER_API_KEY" {
			return "test-key"
		}
		return ""
	}
	if got := providerFromEnv(); got != "together" {
		t.Fatalf("got %q, want together", got)
	}
}

func TestProviderFromEnvUnconfiguredWithoutTogether(t *testing.T) {
	oldGetEnv := getEnv
	defer func() { getEnv = oldGetEnv }()
	getEnv = func(key string) string { return "" }
	if got := providerFromEnv(); got != "unconfigured" {
		t.Fatalf("got %q, want unconfigured", got)
	}
}

func TestProviderFromEnvHonorsLegacyAISwitches(t *testing.T) {
	oldGetEnv := getEnv
	defer func() { getEnv = oldGetEnv }()
	values := map[string]string{
		"AI_ENABLED":                   "false",
		"KOSCHEI_MODEL_ROUTER_ENABLED": "true",
		"TOGETHER_AI_ENABLED":          "true",
		"TOGETHER_API_KEY":             "test-key",
	}
	getEnv = func(key string) string { return values[key] }
	if got := providerFromEnv(); got != "disabled" {
		t.Fatalf("AI_ENABLED=false provider=%q", got)
	}
	values["AI_ENABLED"] = "true"
	values["KOSCHEI_MODEL_ROUTER_ENABLED"] = "false"
	if got := providerFromEnv(); got != "disabled" {
		t.Fatalf("model router disabled provider=%q", got)
	}
	values["KOSCHEI_MODEL_ROUTER_ENABLED"] = "true"
	values["TOGETHER_AI_ENABLED"] = "false"
	if got := providerFromEnv(); got != "unconfigured" {
		t.Fatalf("Together disabled provider=%q", got)
	}
}
