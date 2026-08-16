#!/usr/bin/env bash
set -euo pipefail

# Prepares a dedicated Debian/Ubuntu host for the Node Shield live BPF-LSM proof.
# This script installs user-space build/probe dependencies only. It deliberately
# does NOT rewrite bootloader/kernel LSM settings: enabling BPF LSM is a host
# security decision that may require a reboot and must be performed explicitly.

fail() { echo "[FAIL] $*" >&2; exit 1; }
ok() { echo "[ OK ] $*"; }
info() { echo "[INFO] $*"; }

[[ "$(uname -s)" == "Linux" ]] || fail "Linux is required"
[[ "$(id -u)" -eq 0 ]] || fail "run as root (sudo)"

if [[ -r /etc/os-release ]]; then
  # shellcheck disable=SC1091
  . /etc/os-release
else
  fail "/etc/os-release is unavailable"
fi

case "${ID:-}" in
  ubuntu|debian) ;;
  *) fail "automatic package preparation currently supports Debian/Ubuntu only (detected ${ID:-unknown})" ;;
esac

export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y --no-install-recommends \
  clang llvm bpftool libbpf-dev golang-go git ca-certificates coreutils make gcc libc6-dev

ok "installed clang/llvm, bpftool, libbpf headers, Go bootstrap package, git and build prerequisites"

# The repository currently requires Go 1.25.12. Distribution packages are only
# a bootstrap convenience and MUST NOT be treated as proof that the required
# toolchain is present. Go's automatic toolchain selection may satisfy this if
# supported by the installed bootstrap version; otherwise the host operator
# must install the required official toolchain explicitly.
REQUIRED_GO="1.25.12"
GO_VERSION="$(go env GOVERSION 2>/dev/null || true)"
GO_VERSION="${GO_VERSION#go}"
if [[ "$GO_VERSION" == "$REQUIRED_GO" ]]; then
  ok "Go ${REQUIRED_GO} active"
else
  info "active Go toolchain is ${GO_VERSION:-unknown}; repository requires ${REQUIRED_GO}"
  if GOTOOLCHAIN="go${REQUIRED_GO}" go version >/dev/null 2>&1; then
    ok "Go ${REQUIRED_GO} is available through Go toolchain selection"
  else
    fail "Go ${REQUIRED_GO} is required; install/enable that official toolchain before live proof"
  fi
fi

if [[ -n "${EXPECTED_SHA:-}" ]]; then
  command -v git >/dev/null 2>&1 || fail "git is required for EXPECTED_SHA validation"
  ACTUAL_SHA="$(git rev-parse HEAD 2>/dev/null || true)"
  [[ -n "$ACTUAL_SHA" ]] || fail "EXPECTED_SHA was supplied but current directory is not a Git checkout"
  [[ "$ACTUAL_SHA" == "$EXPECTED_SHA" ]] || fail "checkout identity mismatch: got $ACTUAL_SHA expected $EXPECTED_SHA"
  ok "checkout matches expected head $EXPECTED_SHA"
fi

if [[ -f /sys/fs/cgroup/cgroup.controllers ]]; then
  ok "cgroup v2 detected"
else
  fail "cgroup v2 is not active; host kernel/boot configuration must be fixed before proof"
fi

if [[ -r /sys/kernel/btf/vmlinux ]]; then
  ok "kernel BTF is available"
else
  fail "kernel BTF /sys/kernel/btf/vmlinux is unavailable; use a kernel build/package exposing BTF"
fi

if [[ -r /sys/kernel/security/lsm ]]; then
  lsm_list="$(cat /sys/kernel/security/lsm)"
  info "active LSMs: ${lsm_list}"
  if grep -qw bpf /sys/kernel/security/lsm; then
    ok "BPF LSM is enabled"
  else
    cat >&2 <<'EOF'
[FAIL] BPF LSM is not enabled.
This script will not rewrite bootloader/kernel security configuration automatically.
On a dedicated proof host, enable the BPF LSM using the distribution-supported
kernel command-line/LSM configuration, reboot, and verify that:
  cat /sys/kernel/security/lsm
contains "bpf".
EOF
    exit 2
  fi
else
  fail "/sys/kernel/security/lsm is unavailable"
fi

if [[ ! -w /sys/fs/cgroup ]]; then
  fail "cgroup v2 root is not writable; the proof needs to create disposable child cgroups"
fi
ok "cgroup v2 root is writable"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
READINESS="${SCRIPT_DIR}/nodeshield-bpf-readiness.sh"
[[ -x "$READINESS" ]] || chmod +x "$READINESS"

info "running canonical readiness probe"
"$READINESS"

cat <<EOF
Node Shield proof-host preparation: PASS
Checked Git head: ${EXPECTED_SHA:-not supplied}
Required Go: ${REQUIRED_GO}
Next command from the exact PR-head checkout:
  sudo -E ./scripts/nodeshield-bpf-proof.sh
EOF
