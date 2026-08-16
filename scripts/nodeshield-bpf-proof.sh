#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API="${ROOT}/koschei/api"
BPF="${API}/internal/nodeshield/bpf"
EVIDENCE_DIR="${NODESHIELD_EVIDENCE_DIR:-${ROOT}/artifacts/nodeshield-kernel-proof}"
LOG="${EVIDENCE_DIR}/kernel-proof.log"
REPORT="${EVIDENCE_DIR}/kernel-proof.json"

"${ROOT}/scripts/nodeshield-bpf-readiness.sh"
cleanup(){ rm -rf "${BPF}/out" "${BPF}/vmlinux.h"; }
trap cleanup EXIT
mkdir -p "${EVIDENCE_DIR}"
rm -f "${LOG}" "${REPORT}" "${REPORT}.sha256"

bpftool btf dump file /sys/kernel/btf/vmlinux format c > "${BPF}/vmlinux.h"
TARGET_ARCH="${TARGET_ARCH:-$(uname -m)}"
case "${TARGET_ARCH}" in
  x86_64|amd64|x86) TARGET_ARCH=x86 ;;
  aarch64|arm64) TARGET_ARCH=arm64 ;;
  armv7*|arm) TARGET_ARCH=arm ;;
  riscv64|riscv) TARGET_ARCH=riscv ;;
  *) echo "unsupported TARGET_ARCH: ${TARGET_ARCH}" >&2; exit 1 ;;
esac
(cd "${BPF}" && TARGET_ARCH="${TARGET_ARCH}" bash ./build.sh)

export NODESHIELD_BPF_MANIFEST="${BPF}/out/manifest.json"
(cd "${API}" && go test -tags nodeshield_integration -run '^TestLinuxCOREBackendKernelEnforcement$' -count=1 -v ./internal/nodeshield) 2>&1 | tee "${LOG}"
grep -Fq -- '--- PASS: TestLinuxCOREBackendKernelEnforcement' "${LOG}" || { echo "kernel proof did not execute the required enforcement test" >&2; exit 1; }

COMMIT_SHA="$(git -C "${ROOT}" rev-parse HEAD)"
KERNEL_RELEASE="$(uname -r)"
KERNEL_MACHINE="$(uname -m)"
BPF_MANIFEST_SHA="$(sha256sum "${NODESHIELD_BPF_MANIFEST}" | awk '{print $1}')"
PROOF_LOG_SHA="$(sha256sum "${LOG}" | awk '{print $1}')"
LSM_OBJECT_SHA="$(sha256sum "${BPF}/out/nodeshield_lsm.bpf.o" | awk '{print $1}')"
CONNECT_OBJECT_SHA="$(sha256sum "${BPF}/out/nodeshield_connect.bpf.o" | awk '{print $1}')"
TIMESTAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"

cat > "${REPORT}" <<EOF
{
  "schema": "koschei.nodeshield.kernel-proof.v1",
  "result": "PASS",
  "test": "TestLinuxCOREBackendKernelEnforcement",
  "commit_sha": "${COMMIT_SHA}",
  "timestamp_utc": "${TIMESTAMP}",
  "kernel": {"release": "${KERNEL_RELEASE}", "machine": "${KERNEL_MACHINE}", "bpf_lsm": true, "cgroup_v2": true},
  "bpf": {"target_arch": "${TARGET_ARCH}", "manifest_sha256": "${BPF_MANIFEST_SHA}", "lsm_object_sha256": "${LSM_OBJECT_SHA}", "connect_object_sha256": "${CONNECT_OBJECT_SHA}"},
  "evidence": {"proof_log_sha256": "${PROOF_LOG_SHA}"}
}
EOF

# Store only a relative filename so downloaded evidence remains independently
# verifiable on a different machine/path.
(cd "${EVIDENCE_DIR}" && sha256sum kernel-proof.json > kernel-proof.json.sha256)

echo "Node Shield privileged kernel proof: PASS"
echo "Evidence: ${REPORT}"
echo "Evidence SHA256: $(awk '{print $1}' "${REPORT}.sha256")"
