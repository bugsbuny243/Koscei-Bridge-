#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${ROOT}/koschei/api"
BPF="${API}/internal/nodeshield/bpf"

"${ROOT}/scripts/nodeshield-bpf-readiness.sh"

if [[ ! -f "${BPF}/vmlinux.h" ]]; then
  bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${BPF}/vmlinux.h"
fi

TARGET_ARCH="${TARGET_ARCH:-$(uname -m)}"
case "${TARGET_ARCH}" in
  x86_64|amd64) TARGET_ARCH=x86 ;;
  aarch64|arm64) TARGET_ARCH=arm64 ;;
  armv7*|arm) TARGET_ARCH=arm ;;
  riscv64) TARGET_ARCH=riscv ;;
  *) echo "unsupported TARGET_ARCH: ${TARGET_ARCH}" >&2; exit 1 ;;
esac

(
  cd "${BPF}"
  TARGET_ARCH="${TARGET_ARCH}" bash ./build.sh
)

(
  cd "${API}"
  go test ./internal/nodeshield -run 'TestLinuxCOREIntegration' -count=1 -v
)

echo "Node Shield privileged kernel proof: PASS"
