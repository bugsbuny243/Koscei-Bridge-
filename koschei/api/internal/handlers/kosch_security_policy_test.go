package handlers

import "testing"

func TestKOSCHSecurityPolicyTierCapabilities(t *testing.T) {
	if !koschSecurityCapabilityAllowed("basic", koschCapabilityBasicSecurityScan) {
		t.Fatal("basic tier must allow basic security scan")
	}
	if koschSecurityCapabilityAllowed("basic", koschCapabilityActorGraph) {
		t.Fatal("basic tier must not allow actor graph")
	}
	if !koschSecurityCapabilityAllowed("pro", koschCapabilityActorGraph) {
		t.Fatal("pro tier must allow actor graph")
	}
	if koschSecurityCapabilityAllowed("pro", koschCapabilityDeveloperAPI) {
		t.Fatal("pro tier must not allow developer API")
	}
	if !koschSecurityCapabilityAllowed("enterprise", koschCapabilityDeveloperAPI) {
		t.Fatal("enterprise tier must allow developer API")
	}
}

func TestKOSCHSecurityPolicyNeverGrantsTechnicalAuthority(t *testing.T) {
	for _, tier := range []string{"none", "basic", "pro", "enterprise"} {
		for capability := range koschNeverGrantCapabilities {
			if koschSecurityCapabilityAllowed(tier, capability) {
				t.Fatalf("tier %s must never grant forbidden capability %s", tier, capability)
			}
	}
	}
}

func TestKOSCHSecurityPolicyTierAuthorization(t *testing.T) {
	cases := []struct {
		current  string
		required string
		want     bool
	}{
		{"none", "basic", false},
		{"basic", "basic", true},
		{"basic", "pro", false},
		{"pro", "basic", true},
		{"pro", "pro", true},
		{"pro", "enterprise", false},
		{"enterprise", "basic", true},
		{"enterprise", "pro", true},
		{"enterprise", "enterprise", true},
		{"enterprise", "unknown", false},
	}
	for _, tc := range cases {
		if got := koschTierAuthorizes(tc.current, tc.required); got != tc.want {
			t.Fatalf("koschTierAuthorizes(%q,%q)=%v want %v", tc.current, tc.required, got, tc.want)
		}
	}
}

func TestKOSCHSecurityCapabilitiesReturnsCopy(t *testing.T) {
	first := koschSecurityCapabilitiesForTier("enterprise")
	if len(first) == 0 {
		t.Fatal("enterprise capabilities unexpectedly empty")
	}
	first[0] = "verdict.override"
	second := koschSecurityCapabilitiesForTier("enterprise")
	if len(second) == 0 || second[0] == "verdict.override" {
		t.Fatal("caller mutation must not alter canonical KOSCH capability policy")
	}
}
