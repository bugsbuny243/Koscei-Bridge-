package defense

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestBuildLiteSVMEnvironmentDoesNotInheritSecretsOrNetworkSettings(t *testing.T) {
	t.Setenv("TOGETHER_API_KEY", "secret")
	t.Setenv("SOLANA_RPC_URL", "https://rpc.invalid")
	t.Setenv("HTTPS_PROXY", "https://proxy.invalid")
	plan := testLiteSVMSandboxPlan(t)
	scratch, err := filepath.Abs(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	env, err := buildLiteSVMEnvironment(plan, scratch)
	if err != nil {
		t.Fatal(err)
	}
	joined := "\n" + strings.Join(env, "\n") + "\n"
	for _, forbidden := range []string{"TOGETHER_API_KEY=", "SOLANA_RPC_URL=", "HTTPS_PROXY=", "HTTP_PROXY=", "ALL_PROXY=", "DATABASE_URL="} {
		if strings.Contains(joined, "\n"+forbidden) {
			t.Fatalf("isolated environment inherited forbidden variable %s: %v", forbidden, env)
		}
	}
	for _, required := range []string{
		"CARGO_NET_OFFLINE=true",
		"KOSCHEI_DEFENSE_ISOLATED=1",
		"TZ=UTC",
		"SOURCE_DATE_EPOCH=0",
		"RUSTC=" + plan.EnvironmentTemplate["RUSTC"],
		"HOME=/tmp/koschei-scratch/home",
		"CARGO_TARGET_DIR=/tmp/koschei-scratch/target",
	} {
		if !strings.Contains(joined, "\n"+required+"\n") {
			t.Fatalf("isolated environment is missing %s: %v", required, env)
		}
	}
	for _, dir := range []string{"home", "cargo-home", "rustup-home", "target", "tmp"} {
		info, err := os.Stat(filepath.Join(scratch, dir))
		if err != nil || !info.IsDir() {
			t.Fatalf("bounded scratch directory %s was not created: %v", dir, err)
		}
	}
}

func TestBuildLiteSVMBubblewrapArgsUsesNamespacesAndNoShell(t *testing.T) {
	plan := testLiteSVMSandboxPlan(t)
	base := strings.TrimSpace(os.Getenv("RUNNER_TOOL_CACHE"))
	if base == "" {
		base = "/opt/hostedtoolcache"
	}
	workRoot, err := os.MkdirTemp(base, "koschei-litesvm-test-")
	if err != nil {
		t.Skipf("no writable non-masked sandbox test root: %v", err)
	}
	workRoot, err = filepath.Abs(workRoot)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(workRoot)
	if err := os.Chmod(workRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	input := filepath.Join(workRoot, "input")
	scratch := filepath.Join(workRoot, "scratch")
	for _, path := range []string{input, scratch} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	env, err := buildLiteSVMEnvironment(plan, scratch)
	if err != nil {
		t.Fatal(err)
	}
	args, err := buildLiteSVMBubblewrapArgs(plan, input, scratch, env, false)
	if err != nil {
		t.Fatal(err)
	}
	joined := " " + strings.Join(args, " ") + " "
	for _, required := range []string{
		" --unshare-all ",
		" --die-with-parent ",
		" --new-session ",
		" --ro-bind / / ",
		" --proc /proc ",
		" --dev /dev ",
		" --tmpfs /tmp ",
		" --clearenv ",
		" --ro-bind " + input + " /tmp/koschei-workspace ",
		" --bind " + scratch + " /tmp/koschei-scratch ",
		" --chdir /tmp/koschei-workspace ",
		" -- " + plan.CargoExecutablePath + " test --locked --offline ",
	} {
		if !strings.Contains(joined, required) {
			t.Fatalf("Bubblewrap argv is missing %q: %v", required, args)
		}
	}
	for _, forbidden := range []string{" sh ", " bash ", " -c ", " curl ", " wget "} {
		if strings.Contains(joined, forbidden) {
			t.Fatalf("Bubblewrap argv contains forbidden shell/network token %q: %v", forbidden, args)
		}
	}
	if args[len(args)-4] != plan.CargoExecutablePath || strings.Join(args[len(args)-3:], " ") != "test --locked --offline" {
		t.Fatalf("fixed final command moved or changed: %v", args)
	}
}

func TestBubblewrapPreflightContainsNoSourceMount(t *testing.T) {
	plan := testLiteSVMSandboxPlan(t)
	args, err := buildLiteSVMBubblewrapArgs(plan, "", "", nil, true)
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "koschei-workspace") || strings.Contains(joined, "koschei-scratch") ||
		!strings.Contains(joined, "--unshare-all") || !strings.HasSuffix(joined, plan.SandboxExecutablePath+" --version") {
		t.Fatalf("sandbox preflight crossed the source boundary: %v", args)
	}
}

func TestProcessWorkerJobWithRuntimeFailsClosedBeforeLiteSVMPreparation(t *testing.T) {
	job := WorkerJob{Action: WorkerActionRunLiteSVMHarness, ProfileRef: "KHEP1-example", MaterializationRef: "KHM1-example"}
	base := LiteSVMWorkerRuntime{
		WorkerID: "worker",
		WorkerImageDigest: "sha256:" + strings.Repeat("a", 64),
		WorkerEnabled: true,
		SandboxEnabled: true,
		HarnessExecutionEnabled: true,
		LiteSVMExecutionEnabled: true,
		NetworkIsolated: true,
	}
	cases := []struct {
		name   string
		mutate func(*LiteSVMWorkerRuntime)
		want   string
	}{
		{name: "worker disabled", mutate: func(v *LiteSVMWorkerRuntime) { v.WorkerEnabled = false }, want: "gates are disabled"},
		{name: "sandbox disabled", mutate: func(v *LiteSVMWorkerRuntime) { v.SandboxEnabled = false }, want: "gates are disabled"},
		{name: "harness gate disabled", mutate: func(v *LiteSVMWorkerRuntime) { v.HarnessExecutionEnabled = false }, want: "gates are disabled"},
		{name: "litesvm gate disabled", mutate: func(v *LiteSVMWorkerRuntime) { v.LiteSVMExecutionEnabled = false }, want: "gates are disabled"},
		{name: "network not isolated", mutate: func(v *LiteSVMWorkerRuntime) { v.NetworkIsolated = false }, want: "network boundary"},
		{name: "invalid image", mutate: func(v *LiteSVMWorkerRuntime) { v.WorkerImageDigest = "latest" }, want: "identity or image"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runtime := base
			tc.mutate(&runtime)
			ctx, cancel := context.WithTimeout(context.Background(), time.Second)
			defer cancel()
			if _, err := ProcessWorkerJobWithRuntime(ctx, nil, job, runtime); err == nil || !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(tc.want)) {
				t.Fatalf("expected fail-closed error containing %q, got %v", tc.want, err)
			}
		})
	}
}

func TestLiteSVMFailureClassificationIsConservative(t *testing.T) {
	dependencyCases := []string{
		"no matching package named `litesvm` found",
		"attempting to make an HTTP request, but --offline was specified",
		"failed to download crate",
	}
	for _, text := range dependencyCases {
		if got := classifyLiteSVMProcessFailure("", text); got != "dependency_unavailable_offline" {
			t.Fatalf("dependency failure was misclassified: %q => %s", text, got)
		}
	}
	if got := classifyLiteSVMProcessFailure("test failed", "assertion failed"); got != "process_failed" {
		t.Fatalf("program/test failure was misclassified: %s", got)
	}
	if !isBubblewrapSetupFailure("bwrap: Creating new namespace failed: Operation not permitted") {
		t.Fatal("Bubblewrap setup failure was not recognized as a pre-source rejection")
	}
}

func TestBoundedExecutionBufferConsumesFullWritesAndCapsStoredBytes(t *testing.T) {
	buffer := newBoundedExecutionBuffer(16 * 1024)
	payload := strings.Repeat("x", 20*1024)
	n, err := buffer.Write([]byte(payload))
	if err != nil || n != len(payload) {
		t.Fatalf("bounded writer violated io.Writer contract: n=%d err=%v", n, err)
	}
	if !buffer.Truncated() || len(buffer.String()) != 16*1024 {
		t.Fatalf("bounded writer did not cap output: stored=%d truncated=%t", len(buffer.String()), buffer.Truncated())
	}
}

func testLiteSVMSandboxPlan(t *testing.T) LiteSVMExecutionPlan {
	t.Helper()
	toolDir := t.TempDir()
	cargo := filepath.Join(toolDir, "cargo")
	rustc := filepath.Join(toolDir, "rustc")
	bwrap := filepath.Join(toolDir, "bwrap")
	for path, content := range map[string]string{cargo: "cargo", rustc: "rustc", bwrap: "bwrap"} {
		if err := os.WriteFile(path, []byte(content), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	environment := map[string]string{
		"CARGO_HOME": "/tmp/koschei-scratch/cargo-home",
		"CARGO_NET_OFFLINE": "true",
		"CARGO_TARGET_DIR": "/tmp/koschei-scratch/target",
		"CARGO_TERM_COLOR": "never",
		"GIT_CONFIG_NOSYSTEM": "1",
		"GIT_TERMINAL_PROMPT": "0",
		"HOME": "/tmp/koschei-scratch/home",
		"KOSCHEI_DEFENSE_ISOLATED": "1",
		"LANG": "C.UTF-8",
		"LC_ALL": "C.UTF-8",
		"PATH": toolDir,
		"RUST_BACKTRACE": "0",
		"RUSTC": rustc,
		"RUSTUP_HOME": "/tmp/koschei-scratch/rustup-home",
		"SOURCE_DATE_EPOCH": "0",
		"TERM": "dumb",
		"TMPDIR": "/tmp/koschei-scratch/tmp",
		"TZ": "UTC",
	}
	policy := liteSVMBubblewrapPolicy(environment, cargo, bwrap)
	return LiteSVMExecutionPlan{
		CargoExecutablePath: cargo,
		CargoExecutableHash: "sha256:" + strings.Repeat("a", 64),
		SandboxExecutablePath: bwrap,
		SandboxExecutableHash: "sha256:" + strings.Repeat("b", 64),
		EnvironmentTemplate: environment,
		EnvironmentHash: hashValue(environment),
		SandboxPolicy: policy,
		SandboxPolicyHash: hashValue(policy),
	}
}
