package defense

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"time"
)

const liteSVMSandboxPreflightTimeout = 15 * time.Second

type LiteSVMWorkerRuntime struct {
	WorkerID                string
	WorkerImageDigest       string
	WorkRoot                string
	WorkerEnabled           bool
	SandboxEnabled          bool
	HarnessExecutionEnabled bool
	LiteSVMExecutionEnabled bool
	NetworkIsolated         bool
}

// ProcessWorkerJobWithRuntime preserves the legacy verification path and adds
// the Phase 12C action only when every worker-side gate is explicitly true.
func ProcessWorkerJobWithRuntime(ctx context.Context, db *sql.DB, job WorkerJob, runtime LiteSVMWorkerRuntime) (map[string]any, error) {
	if job.Action != WorkerActionRunLiteSVMHarness {
		return ProcessWorkerJob(ctx, db, job, runtime.SandboxEnabled)
	}
	attempt, err := ExecuteLiteSVMWorkerJob(ctx, db, job, runtime)
	if err != nil {
		return nil, err
	}
	return map[string]any{
		"action":                   job.Action,
		"attempt":                  attempt,
		"worker_execution":         true,
		"network_access":           false,
		"dependency_resolution":    false,
		"wallet_material_accessed": false,
		"mainnet_rpc_accessed":     false,
		"mainnet_transaction_sent": false,
		"verdict_authority":        false,
	}, nil
}

// ExecuteLiteSVMWorkerJob is the only Phase 12C process-launch boundary. It
// launches the pinned Bubblewrap executable directly, never Cargo or a shell.
// Cargo runs only as the fixed final command inside a new namespace set.
func ExecuteLiteSVMWorkerJob(ctx context.Context, db *sql.DB, job WorkerJob, runtime LiteSVMWorkerRuntime) (LiteSVMExecutionAttempt, error) {
	if !runtime.WorkerEnabled || !runtime.SandboxEnabled || !runtime.HarnessExecutionEnabled || !runtime.LiteSVMExecutionEnabled {
		return LiteSVMExecutionAttempt{}, errors.New("Phase 12C worker execution gates are disabled")
	}
	if !runtime.NetworkIsolated {
		return LiteSVMExecutionAttempt{}, errors.New("isolated worker network boundary is not attested")
	}
	if strings.TrimSpace(runtime.WorkerID) == "" || normalizeDefenseSHA256Digest(runtime.WorkerImageDigest) == "" {
		return LiteSVMExecutionAttempt{}, errors.New("live worker identity or image digest is unavailable")
	}
	workRoot, err := validateLiteSVMWorkRoot(runtime.WorkRoot)
	if err != nil {
		return LiteSVMExecutionAttempt{}, err
	}
	if job.Action != WorkerActionRunLiteSVMHarness || job.ProfileRef == "" || job.MaterializationRef == "" {
		return LiteSVMExecutionAttempt{}, errors.New("LiteSVM worker job is incomplete")
	}
	plan, err := PrepareLiteSVMExecution(ctx, db, job.JobRef, job.ProfileRef, job.MaterializationRef, runtime.WorkerID, runtime.WorkerImageDigest)
	if err != nil {
		return LiteSVMExecutionAttempt{}, err
	}

	startedAt := time.Now().UTC()
	dependencies, err := AuthorizeOfflineDependencyRuntime(ctx, db, runtime.WorkerID, runtime.WorkerImageDigest, job.MaterializationRef)
	if err != nil {
		return persistLiteSVMStartRejection(ctx, db, plan, job.Attempts, startedAt, OfflineDependencyTerminationReason(err), err)
	}
	if err := BindOfflineDependencyAuthorizationToPlan(&plan, dependencies); err != nil {
		return persistLiteSVMStartRejection(ctx, db, plan, job.Attempts, startedAt, OfflineDependencyTerminationReason(err), err)
	}

	inputRoot, err := os.MkdirTemp(workRoot, "input-")
	if err != nil {
		return persistLiteSVMStartRejection(ctx, db, plan, job.Attempts, startedAt, "sandbox_unavailable", err)
	}
	defer removeLiteSVMTree(inputRoot)
	scratchRoot, err := os.MkdirTemp(workRoot, "scratch-")
	if err != nil {
		return persistLiteSVMStartRejection(ctx, db, plan, job.Attempts, startedAt, "sandbox_unavailable", err)
	}
	defer removeLiteSVMTree(scratchRoot)
	if err := materializeBundle(inputRoot, plan.Bundle); err != nil {
		return persistLiteSVMStartRejection(ctx, db, plan, job.Attempts, startedAt, "materialized_artifact_mismatch", err)
	}
	if err := makeLiteSVMInputReadOnly(inputRoot); err != nil {
		return persistLiteSVMStartRejection(ctx, db, plan, job.Attempts, startedAt, "sandbox_unavailable", err)
	}
	environment, err := buildLiteSVMEnvironment(plan, scratchRoot)
	if err != nil {
		return persistLiteSVMStartRejection(ctx, db, plan, job.Attempts, startedAt, "sandbox_unavailable", err)
	}
	if err := preflightLiteSVMSandbox(ctx, plan, environment); err != nil {
		return persistLiteSVMStartRejection(ctx, db, plan, job.Attempts, startedAt, "sandbox_unavailable", err)
	}
	args, err := buildLiteSVMBubblewrapArgs(plan, inputRoot, scratchRoot, environment, false)
	if err != nil {
		return persistLiteSVMStartRejection(ctx, db, plan, job.Attempts, startedAt, "sandbox_unavailable", err)
	}
	args, err = AppendOfflineDependencySandboxArgs(args, dependencies)
	if err != nil {
		return persistLiteSVMStartRejection(ctx, db, plan, job.Attempts, startedAt, OfflineDependencyTerminationReason(err), err)
	}

	maxDuration := time.Duration(plan.MaxDurationSeconds) * time.Second
	runCtx, cancel := context.WithTimeout(ctx, maxDuration)
	defer cancel()
	stdout := newBoundedExecutionBuffer(plan.MaxOutputBytes)
	stderr := newBoundedExecutionBuffer(plan.MaxOutputBytes)
	cmd := exec.Command(plan.SandboxExecutablePath, args...)
	cmd.Env = []string{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return persistLiteSVMStartRejection(ctx, db, plan, job.Attempts, startedAt, "sandbox_unavailable", err)
	}

	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	status := "completed"
	terminationReason := "process_exited"
	var runErr error
	select {
	case runErr = <-done:
	case <-runCtx.Done():
		killExecutionProcessGroup(cmd)
		runErr = <-done
		if errors.Is(ctx.Err(), context.Canceled) {
			status = "cancelled"
			terminationReason = "execution_cancelled"
		} else {
			status = "timed_out"
			terminationReason = "execution_timeout"
		}
	}
	// Bubblewrap uses --die-with-parent, but also kill the host process group after
	// every terminal result so a broken test cannot retain detached descendants.
	killExecutionProcessGroup(cmd)
	completedAt := time.Now().UTC()
	exitCode := 0
	if cmd.ProcessState != nil {
		exitCode = cmd.ProcessState.ExitCode()
	}
	if status == "completed" && runErr != nil {
		if isBubblewrapSetupFailure(stderr.String()) {
			return persistLiteSVMRejectedProcessResult(ctx, db, plan, job.Attempts, startedAt, completedAt, exitCode, stdout, stderr, "sandbox_unavailable")
		}
		status = "failed"
		terminationReason = classifyLiteSVMProcessFailure(stdout.String(), stderr.String())
	}
	limitations := []string{
		"The command ran in a Bubblewrap network/PID namespace and the worker reported a configured no-egress deployment boundary; application evidence cannot independently prove the external deployment policy.",
		"The exact offline dependency inventory and read-only Cargo vendor/config mounts are retained in immutable sandbox-policy evidence.",
		"CPU, memory and writable-storage ceilings also depend on the separately reviewed worker/container resource policy.",
		"A single deterministic harness result does not establish exploitability, reachability, asset impact, proof-of-fix or program safety.",
	}
	if stdout.Truncated() || stderr.Truncated() {
		limitations = append(limitations, "Process output exceeded the immutable profile bound and was truncated deterministically.")
	}
	attempt, persistErr := PersistLiteSVMExecutionAttempt(ctx, db, plan, LiteSVMExecutionOutcome{
		AttemptNumber:     job.Attempts,
		Status:            status,
		StartedAt:         startedAt,
		CompletedAt:       completedAt,
		ExitCode:          &exitCode,
		TerminationReason: terminationReason,
		Stdout:            stdout.String(),
		Stderr:            stderr.String(),
		StdoutTruncated:   stdout.Truncated(),
		StderrTruncated:   stderr.Truncated(),
		SourceExecuted:    true,
		HarnessExecuted:   true,
		Limitations:       limitations,
	})
	if persistErr != nil {
		return LiteSVMExecutionAttempt{}, persistErr
	}
	return attempt, nil
}

func preflightLiteSVMSandbox(ctx context.Context, plan LiteSVMExecutionPlan, environment []string) error {
	preflightCtx, cancel := context.WithTimeout(ctx, liteSVMSandboxPreflightTimeout)
	defer cancel()
	args, err := buildLiteSVMBubblewrapArgs(plan, "", "", environment, true)
	if err != nil {
		return err
	}
	stdout := newBoundedExecutionBuffer(16 * 1024)
	stderr := newBoundedExecutionBuffer(16 * 1024)
	cmd := exec.Command(plan.SandboxExecutablePath, args...)
	cmd.Env = []string{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return err
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		killExecutionProcessGroup(cmd)
		if err != nil {
			return fmt.Errorf("bubblewrap namespace preflight failed: %s", boundedFailureText(stderr.String()))
		}
		return nil
	case <-preflightCtx.Done():
		killExecutionProcessGroup(cmd)
		<-done
		return errors.New("bubblewrap namespace preflight timed out")
	}
}

func buildLiteSVMBubblewrapArgs(plan LiteSVMExecutionPlan, inputRoot, scratchRoot string, environment []string, preflight bool) ([]string, error) {
	if strings.TrimSpace(plan.SandboxExecutablePath) == "" || !filepath.IsAbs(plan.SandboxExecutablePath) ||
		normalizeDefenseSHA256Digest(plan.SandboxExecutableHash) == "" {
		return nil, errors.New("pinned Bubblewrap executable evidence is unavailable")
	}
	if len(plan.SandboxPolicy) == 0 || plan.SandboxPolicyHash == "" || plan.SandboxPolicyHash != hashValue(plan.SandboxPolicy) {
		return nil, errors.New("Bubblewrap sandbox policy evidence is invalid")
	}
	if strings.TrimSpace(fmt.Sprint(plan.SandboxPolicy["policy_version"])) != liteSVMSandboxPolicyVersion ||
		plan.SandboxPolicy["shell"] != false || plan.SandboxPolicy["unshare_all"] != true ||
		plan.SandboxPolicy["clear_environment"] != true || plan.SandboxPolicy["read_only_root"] != true ||
		plan.SandboxPolicy["host_work_root_masked"] != true {
		return nil, errors.New("Bubblewrap sandbox policy does not match Phase 12C")
	}
	args := []string{
		"--unshare-all",
		"--die-with-parent",
		"--new-session",
		"--ro-bind", "/", "/",
		"--proc", "/proc",
		"--dev", "/dev",
		"--tmpfs", "/tmp",
		"--tmpfs", "/run",
		"--tmpfs", "/var/tmp",
		"--tmpfs", "/sys",
		"--tmpfs", "/root",
		"--tmpfs", "/home",
		"--hostname", "koschei-defense",
		"--clearenv",
	}
	if preflight {
		args = append(args, "--setenv", "PATH", filepath.Dir(plan.SandboxExecutablePath))
		args = append(args, "--", plan.SandboxExecutablePath, "--version")
		return args, nil
	}
	inputRoot = filepath.Clean(inputRoot)
	scratchRoot = filepath.Clean(scratchRoot)
	workRoot := filepath.Dir(inputRoot)
	if !filepath.IsAbs(inputRoot) || !filepath.IsAbs(scratchRoot) || inputRoot == scratchRoot ||
		workRoot != filepath.Dir(scratchRoot) {
		return nil, errors.New("Bubblewrap input and scratch roots must be distinct children of one absolute work root")
	}
	if _, err := validateLiteSVMWorkRoot(workRoot); err != nil {
		return nil, err
	}
	if err := validateLiteSVMEnvironment(plan, environment); err != nil {
		return nil, err
	}
	args = append(args,
		"--dir", "/tmp/koschei-workspace",
		"--dir", "/tmp/koschei-scratch",
		"--ro-bind", inputRoot, "/tmp/koschei-workspace",
		"--bind", scratchRoot, "/tmp/koschei-scratch",
		// Mask the original host-side input/scratch paths after their dedicated
		// mounts are installed so source cannot address them through the root bind.
		"--tmpfs", workRoot,
		"--chdir", "/tmp/koschei-workspace",
	)
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || strings.TrimSpace(key) == "" {
			return nil, errors.New("invalid LiteSVM environment entry")
		}
		args = append(args, "--setenv", key, value)
	}
	// Mask the launcher itself inside the sandbox to prevent nested Bubblewrap.
	args = append(args, "--ro-bind", "/dev/null", plan.SandboxExecutablePath)
	args = append(args, "--", plan.CargoExecutablePath, "test", "--locked", "--offline")
	return args, nil
}

func buildLiteSVMEnvironment(plan LiteSVMExecutionPlan, scratchRoot string) ([]string, error) {
	scratchRoot = filepath.Clean(scratchRoot)
	if !filepath.IsAbs(scratchRoot) {
		return nil, errors.New("LiteSVM scratch root must be absolute")
	}
	for _, relative := range []string{"home", "cargo-home", "rustup-home", "target", "tmp"} {
		if err := os.MkdirAll(filepath.Join(scratchRoot, relative), 0o700); err != nil {
			return nil, err
		}
	}
	// Bubblewrap overlays the immutable Cargo configuration on this placeholder.
	// Creating it inside the bounded scratch tree avoids relying on implicit file
	// creation behavior at the namespace boundary.
	if err := os.WriteFile(filepath.Join(scratchRoot, "cargo-home", "config.toml"), nil, 0o600); err != nil {
		return nil, err
	}
	if len(plan.EnvironmentTemplate) == 0 || plan.EnvironmentHash == "" || plan.EnvironmentHash != hashValue(plan.EnvironmentTemplate) {
		return nil, errors.New("LiteSVM environment template evidence is invalid")
	}
	keys := make([]string, 0, len(plan.EnvironmentTemplate))
	for key := range plan.EnvironmentTemplate {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+plan.EnvironmentTemplate[key])
	}
	if err := validateLiteSVMEnvironment(plan, out); err != nil {
		return nil, err
	}
	return out, nil
}

func validateLiteSVMEnvironment(plan LiteSVMExecutionPlan, environment []string) error {
	actual := map[string]string{}
	seen := map[string]bool{}
	for _, entry := range environment {
		key, value, ok := strings.Cut(entry, "=")
		if !ok || key == "" || seen[key] {
			return errors.New("LiteSVM environment contains an invalid or duplicate key")
		}
		seen[key] = true
		actual[key] = value
	}
	if hashValue(actual) != plan.EnvironmentHash || len(actual) != len(plan.EnvironmentTemplate) {
		return errors.New("LiteSVM environment differs from the immutable template")
	}
	for key, value := range plan.EnvironmentTemplate {
		if actual[key] != value {
			return errors.New("LiteSVM environment differs from the immutable template")
		}
	}
	for _, forbidden := range []string{"DATABASE_URL", "TOGETHER_API_KEY", "SOLANA_RPC_URL", "HELIUS_API_KEY", "ALCHEMY_API_KEY", "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"} {
		if _, ok := actual[forbidden]; ok {
			return fmt.Errorf("forbidden environment key present: %s", forbidden)
		}
	}
	if actual["CARGO_NET_OFFLINE"] != "true" || actual["KOSCHEI_DEFENSE_ISOLATED"] != "1" ||
		actual["HOME"] != "/tmp/koschei-scratch/home" || actual["CARGO_HOME"] != "/tmp/koschei-scratch/cargo-home" ||
		actual["CARGO_TARGET_DIR"] != "/tmp/koschei-scratch/target" || actual["TMPDIR"] != "/tmp/koschei-scratch/tmp" {
		return errors.New("LiteSVM environment is not bound to the isolated scratch mount")
	}
	return nil
}

func validateLiteSVMWorkRoot(value string) (string, error) {
	value = filepath.Clean(strings.TrimSpace(value))
	if value == "" || value == "." || value == string(os.PathSeparator) || !filepath.IsAbs(value) {
		return "", errors.New("KOSCHEI_DEFENSE_WORK_ROOT must be a dedicated absolute path")
	}
	for _, blocked := range []string{"/tmp", "/run", "/var/tmp", "/dev", "/proc", "/sys", "/root", "/home"} {
		if value == blocked || strings.HasPrefix(value, blocked+string(os.PathSeparator)) {
			return "", errors.New("KOSCHEI_DEFENSE_WORK_ROOT cannot be inside a masked or sensitive sandbox path")
		}
	}
	if err := os.MkdirAll(value, 0o700); err != nil {
		return "", err
	}
	info, err := os.Lstat(value)
	if err != nil {
		return "", err
	}
	if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0o077 != 0 {
		return "", errors.New("KOSCHEI_DEFENSE_WORK_ROOT must be a private non-symlink directory")
	}
	resolved, err := filepath.EvalSymlinks(value)
	if err != nil || filepath.Clean(resolved) != value {
		return "", errors.New("KOSCHEI_DEFENSE_WORK_ROOT must not traverse symlinks")
	}
	return value, nil
}

func persistLiteSVMRejectedProcessResult(ctx context.Context, db *sql.DB, plan LiteSVMExecutionPlan, attemptNumber int, startedAt, completedAt time.Time, exitCode int, stdout, stderr *boundedExecutionBuffer, reason string) (LiteSVMExecutionAttempt, error) {
	return PersistLiteSVMExecutionAttempt(ctx, db, plan, LiteSVMExecutionOutcome{
		AttemptNumber:     attemptNumber,
		Status:            "rejected",
		StartedAt:         startedAt,
		CompletedAt:       completedAt,
		ExitCode:          &exitCode,
		TerminationReason: reason,
		Stdout:            stdout.String(),
		Stderr:            stderr.String(),
		StdoutTruncated:   stdout.Truncated(),
		StderrTruncated:   stderr.Truncated(),
		SourceExecuted:    false,
		HarnessExecuted:   false,
		Limitations:       []string{"Bubblewrap failed before the fixed Cargo command could be treated as launched."},
	})
}

func persistLiteSVMStartRejection(ctx context.Context, db *sql.DB, plan LiteSVMExecutionPlan, attemptNumber int, startedAt time.Time, reason string, cause error) (LiteSVMExecutionAttempt, error) {
	limitations := []string{}
	if cause != nil {
		limitations = append(limitations, boundedFailureText(cause.Error()))
	}
	return PersistLiteSVMExecutionAttempt(ctx, db, plan, LiteSVMExecutionOutcome{
		AttemptNumber:     attemptNumber,
		Status:            "rejected",
		StartedAt:         startedAt,
		CompletedAt:       time.Now().UTC(),
		TerminationReason: reason,
		SourceExecuted:    false,
		HarnessExecuted:   false,
		Limitations:       limitations,
	})
}

func makeLiteSVMInputReadOnly(root string) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.Chmod(path, 0o500)
		}
		return os.Chmod(path, 0o400)
	})
}

func removeLiteSVMTree(root string) {
	_ = filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info == nil {
			return nil
		}
		if info.IsDir() {
			_ = os.Chmod(path, 0o700)
		} else {
			_ = os.Chmod(path, 0o600)
		}
		return nil
	})
	_ = os.RemoveAll(root)
}

func killExecutionProcessGroup(cmd *exec.Cmd) {
	if cmd == nil || cmd.Process == nil {
		return
	}
	_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
}

func isBubblewrapSetupFailure(stderr string) bool {
	value := strings.ToLower(strings.TrimSpace(stderr))
	return strings.HasPrefix(value, "bwrap:") || strings.Contains(value, "bubblewrap") ||
		strings.Contains(value, "creating new namespace failed") || strings.Contains(value, "operation not permitted")
}

func classifyLiteSVMProcessFailure(stdout, stderr string) string {
	combined := strings.ToLower(stdout + "\n" + stderr)
	patterns := []string{
		"no matching package named",
		"failed to download",
		"attempting to make an http request, but --offline was specified",
		"unable to update registry",
		"could not find",
	}
	for _, pattern := range patterns {
		if strings.Contains(combined, pattern) {
			return "dependency_unavailable_offline"
		}
	}
	return "process_failed"
}

func boundedFailureText(value string) string {
	value = strings.TrimSpace(strings.ToValidUTF8(value, "\uFFFD"))
	if len(value) > 2000 {
		value = value[:2000]
	}
	return value
}

type boundedExecutionBuffer struct {
	buffer    bytes.Buffer
	remaining int
	truncated bool
}

func newBoundedExecutionBuffer(maximum int) *boundedExecutionBuffer {
	if maximum < 16*1024 || maximum > 1024*1024 {
		maximum = 256 * 1024
	}
	return &boundedExecutionBuffer{remaining: maximum}
}

func (b *boundedExecutionBuffer) Write(p []byte) (int, error) {
	original := len(p)
	if b.remaining <= 0 {
		b.truncated = b.truncated || original > 0
		return original, nil
	}
	write := p
	if len(write) > b.remaining {
		write = write[:b.remaining]
		b.truncated = true
	}
	_, _ = b.buffer.Write(write)
	b.remaining -= len(write)
	return original, nil
}

func (b *boundedExecutionBuffer) String() string {
	return strings.ToValidUTF8(b.buffer.String(), "\uFFFD")
}

func (b *boundedExecutionBuffer) Truncated() bool { return b.truncated }
