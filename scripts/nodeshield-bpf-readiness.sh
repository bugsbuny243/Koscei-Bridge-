#!/usr/bin/env bash
set -euo pipefail

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok() { echo "[ OK ] $*"; }

[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
[[ "$(id -u)" -eq 0 ]] || fail "root privileges are required for live BPF proof"

[[ -r /sys/kernel/security/lsm ]] || fail "/sys/kernel/security/lsm is unavailable"
if grep -qw bpf /sys/kernel/security/lsm; then
  ok "BPF LSM is enabled"
else
  fail "BPF LSM is not enabled in /sys/kernel/security/lsm"
fi

[[ -f /sys/fs/cgroup/cgroup.controllers ]] || fail "cgroup v2 is required"
[[ -w /sys/fs/cgroup ]] || fail "cgroup v2 root must be writable to create disposable proof cgroups"
ok "writable cgroup v2 detected"

command -v clang >/dev/null 2>&1 || fail "clang is required"
command -v bpftool >/dev/null 2>&1 || fail "bpftool is required"
command -v go >/dev/null 2>&1 || fail "Go is required"
command -v git >/dev/null 2>&1 || fail "git is required for commit-bound evidence"
command -v sha256sum >/dev/null 2>&1 || fail "sha256sum is required for proof evidence"
command -v mktemp >/dev/null 2>&1 || fail "mktemp is required for a private feature-probe file"
ok "clang, bpftool, Go, git, sha256sum, and mktemp detected"

[[ -r /sys/kernel/btf/vmlinux ]] || fail "kernel BTF /sys/kernel/btf/vmlinux is required for CO-RE"
ok "kernel BTF available"

[[ -r /usr/include/bpf/bpf_helpers.h ]] || fail "libbpf development headers are required"
ok "libbpf headers available"

PROBE_FILE="$(mktemp -p "${TMPDIR:-/tmp}" nodeshield-bpf-feature-probe.XXXXXX)"
cleanup() { rm -f -- "$PROBE_FILE"; }
trap cleanup EXIT HUP INT TERM
chmod 600 "$PROBE_FILE"

if bpftool feature probe kernel >"$PROBE_FILE" 2>&1; then
  ok "bpftool kernel feature probe succeeded"
else
  cat "$PROBE_FILE" >&2 || true
  fail "bpftool kernel feature probe failed"
fi

if grep -q 'program_type lsm is available' "$PROBE_FILE"; then
  ok "BPF LSM program type available"
else
  fail "bpftool did not report BPF LSM program type availability"
fi

if grep -q 'program_type cgroup_sock_addr is available' "$PROBE_FILE"; then
  ok "cgroup socket-address BPF program type available"
else
  fail "bpftool did not report cgroup socket-address program type availability"
fi

echo "Node Shield BPF runner readiness: PASS"
