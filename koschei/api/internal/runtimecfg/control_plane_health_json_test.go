package runtimecfg

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestControlPlaneHealthJSONPublishesOnlySummary(t *testing.T) {
	report := ControlPlaneHealth{
		Version:       "runtime-control-plane/v1",
		OK:            true,
		Controls:      20,
		Active:        17,
		Disabled:      1,
		Defaulted:     2,
		Shadowed:      0,
		Misconfigured: 0,
		Items: []ControlPlaneItem{
			{Name: "TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY", State: ControlStateActive, Detail: "credential configured", Secret: true},
			{Name: "SOLSCAN_API_KEY", State: ControlStateActive, Detail: "credential configured", Secret: true},
		},
	}

	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	body := string(encoded)
	for _, forbidden := range []string{
		"items",
		"TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY",
		"SOLSCAN_API_KEY",
		"credential configured",
	} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("public control-plane JSON exposed %q: %s", forbidden, body)
		}
	}
	for _, marker := range []string{
		`"version":"runtime-control-plane/v1"`,
		`"ok":true`,
		`"controls":20`,
		`"active":17`,
		`"misconfigured":0`,
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("public control-plane JSON missing %q: %s", marker, body)
		}
	}
}
