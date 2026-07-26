package main

import "testing"

func TestEnvBoolDefaultUsesFallbackWhenUnset(t *testing.T) {
	t.Setenv("KOSCHEI_DATABASE_POLLING_WORKERS_ENABLED", "")
	if envBoolDefault("KOSCHEI_DATABASE_POLLING_WORKERS_ENABLED", false) {
		t.Fatal("unset production guard must keep polling disabled")
	}
	if !envBoolDefault("KOSCHEI_DATABASE_POLLING_WORKERS_ENABLED", true) {
		t.Fatal("development fallback must remain enabled")
	}
}

func TestEnvBoolDefaultParsesExplicitValues(t *testing.T) {
	t.Setenv("KOSCHEI_DATABASE_POLLING_WORKERS_ENABLED", "true")
	if !envBoolDefault("KOSCHEI_DATABASE_POLLING_WORKERS_ENABLED", false) {
		t.Fatal("explicit true was ignored")
	}
	t.Setenv("KOSCHEI_DATABASE_POLLING_WORKERS_ENABLED", "0")
	if envBoolDefault("KOSCHEI_DATABASE_POLLING_WORKERS_ENABLED", true) {
		t.Fatal("explicit false was ignored")
	}
}
