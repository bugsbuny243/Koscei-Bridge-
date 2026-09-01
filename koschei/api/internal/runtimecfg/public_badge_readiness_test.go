package runtimecfg

import "testing"

func TestPublicBadgeDefaultsDisabledUntilCanonicalReadiness(t *testing.T) {
	cfg := LoadWith(func(string) string { return "" })
	if cfg.PublicBadgeEnabled {
		t.Fatal("public badge must default disabled until a canonical public decision path is production-ready")
	}
}

func TestPublicBadgeSupportsExplicitOptIn(t *testing.T) {
	cfg := LoadWith(func(key string) string {
		if key == "KOSCHEI_PUBLIC_BADGE_ENABLED" {
			return "true"
		}
		return ""
	})
	if !cfg.PublicBadgeEnabled {
		t.Fatal("explicit public badge opt-in should remain supported")
	}
}

func TestPublicBadgeControlPlaneReportsDisabledDefault(t *testing.T) {
	health := ControlPlaneHealthWith(func(string) string { return "" })
	item := findControl(health.Items, "KOSCHEI_PUBLIC_BADGE_ENABLED")
	if item == nil {
		t.Fatal("public badge control missing from control-plane health")
	}
	if item.State != ControlStateDefaulted {
		t.Fatalf("state=%q want=%q", item.State, ControlStateDefaulted)
	}
	if item.Detail != "runtime default disabled" {
		t.Fatalf("detail=%q", item.Detail)
	}
}
