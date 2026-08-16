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
ok "cgroup v2 detected"

command -v clang >/dev/null 2>&1 || fail "clang is required"
command -v bpftool >/dev/null 2>&1 || fail "bpftool is required"
command -v go >/dev/null 2>&1 || fail "Go is required"
[[ -r /usr/include/bpf/bpf_helpers.h ]] || fail "libbpf headers are required"
ok "clang, bpftool, Go, and libbpf headers detected"

if [[ ! -r /sys/kernel/btf/vmlinux ]]; then
  fail "kernel BTF /sys/kernel/btf/vmlinux is required for CO-RE"
fi
ok "kernel BTF available"

if bpftool feature probe kernel >/tmp/nodeshield-bpf-feature-probe.txt 2>&1; then
  ok "bpftool kernel feature probe succeeded"
else
  cat /tmp/nodeshield-bpf-feature-probe.txt >&2 || true
  fail "bpftool kernel feature probe failed"
fi

echo "Node Shield BPF runner readiness: PASS"
