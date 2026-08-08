package runtimecfg

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRecoveredControlPlaneContractWiredAndDocumented(t *testing.T) {
	names := RecoveredControlPlaneEnvNames()
	if len(names) != 20 {
		t.Fatalf("recovered control count=%d want=20", len(names))
	}
	seen := map[string]struct{}{}
	for _, name := range names {
		if _, ok := seen[name]; ok {
			t.Fatalf("duplicate recovered control %q", name)
		}
		seen[name] = struct{}{}
	}

	configSource, err := os.ReadFile("config.go")
	if err != nil {
		t.Fatal(err)
	}
	envExample, err := os.ReadFile("../../../../.env.example")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		if !strings.Contains(string(configSource), `"`+name+`"`) {
			t.Errorf("%s is in the recovered contract but is not read by config.go", name)
		}
		if !strings.Contains(string(envExample), name+"=") {
			t.Errorf("%s is in the recovered contract but is not documented in .env.example", name)
		}
	}
}

func TestControlPlaneHealthDetectsShadowingAndInvalidBounds(t *testing.T) {
	values := map[string]string{
		"AI_ENABLED":              "false",
		"AI_PROVIDER":             "together",
		"TOGETHER_AI_ENABLED":     "true",
		"WORKER_MAX_BUILD_THREADS": "9999",
	}
	report := ControlPlaneHealthWith(mapGetter(values))
	if report.OK {
		t.Fatal("drift report unexpectedly healthy")
	}
	if got := controlState(report, "AI_PROVIDER"); got != ControlStateShadowed {
		t.Fatalf("AI_PROVIDER state=%q want=%q", got, ControlStateShadowed)
	}
	if got := controlState(report, "TOGETHER_AI_ENABLED"); got != ControlStateShadowed {
		t.Fatalf("TOGETHER_AI_ENABLED state=%q want=%q", got, ControlStateShadowed)
	}
	if got := controlState(report, "WORKER_MAX_BUILD_THREADS"); got != ControlStateMisconfigured {
		t.Fatalf("WORKER_MAX_BUILD_THREADS state=%q want=%q", got, ControlStateMisconfigured)
	}
}

func TestControlPlaneHealthDetectsRequiredPermitDependency(t *testing.T) {
	values := map[string]string{
		"TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT": "true",
		"TRANSACTION_GUARD_ENFORCEMENT_KEY_ID":          "",
		"TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY":     "",
	}
	report := ControlPlaneHealthWith(mapGetter(values))
	if report.OK || report.Misconfigured < 3 {
		t.Fatalf("required permit dependency not detected: %#v", report)
	}
	for _, name := range []string{
		"TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT",
		"TRANSACTION_GUARD_ENFORCEMENT_KEY_ID",
		"TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY",
	} {
		if got := controlState(report, name); got != ControlStateMisconfigured {
			t.Fatalf("%s state=%q want=%q", name, got, ControlStateMisconfigured)
		}
	}
}

func TestControlPlaneHealthDoesNotLeakSecrets(t *testing.T) {
	secret := "this-must-never-appear-in-config-output"
	values := map[string]string{
		"SOLSCAN_API_KEY":                              secret,
		"TRANSACTION_GUARD_ENFORCEMENT_PRIVATE_KEY":   secret,
		"TRANSACTION_GUARD_ENFORCEMENT_KEY_ID":        "guard-key-v1",
		"TRANSACTION_GUARD_REQUIRE_ENFORCEMENT_PERMIT": "false",
	}
	report := ControlPlaneHealthWith(mapGetter(values))
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), secret) {
		t.Fatal("control plane health leaked a secret value")
	}
	if got := controlState(report, "SOLSCAN_API_KEY"); got != ControlStateActive {
		t.Fatalf("SOLSCAN_API_KEY state=%q want=%q", got, ControlStateActive)
	}
}

func TestControlPlaneHealthHasExactlyOneItemPerRecoveredControl(t *testing.T) {
	report := ControlPlaneHealthWith(mapGetter(map[string]string{}))
	if report.Controls != len(RecoveredControlPlaneEnvNames()) || len(report.Items) != report.Controls {
		t.Fatalf("controls=%d items=%d contract=%d", report.Controls, len(report.Items), len(RecoveredControlPlaneEnvNames()))
	}
	seen := map[string]int{}
	for _, item := range report.Items {
		seen[item.Name]++
	}
	for _, name := range RecoveredControlPlaneEnvNames() {
		if seen[name] != 1 {
			t.Fatalf("control %s appears %d times", name, seen[name])
		}
	}
}

func mapGetter(values map[string]string) Getter {
	return func(name string) string { return values[name] }
}

func controlState(report ControlPlaneHealth, name string) string {
	for _, item := range report.Items {
		if item.Name == name {
			return item.State
		}
	}
	return ""
}
