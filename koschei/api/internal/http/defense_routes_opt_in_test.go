package http

import "testing"

func TestDefenseOSRoutesDefaultOff(t *testing.T) {
	t.Setenv("KOSCHEI_DEFENSE_OS_ENABLED", "")
	if defenseOSRoutesEnabled() {
		t.Fatal("Defense OS routes must be disabled by default")
	}
}

func TestDefenseOSRoutesRequireExplicitOptIn(t *testing.T) {
	for _, value := range []string{"1", "true", "YES", "on"} {
		t.Run(value, func(t *testing.T) {
			t.Setenv("KOSCHEI_DEFENSE_OS_ENABLED", value)
			if !defenseOSRoutesEnabled() {
				t.Fatalf("expected %q to enable Defense OS routes", value)
			}
		})
	}
}
