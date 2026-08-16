#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
OUT="${ROOT}/out"
CLANG="${CLANG:-clang}"
TARGET_ARCH="${TARGET_ARCH:-x86}"

mkdir -p "${OUT}"

command -v "${CLANG}" >/dev/null 2>&1 || {
  echo "clang is required" >&2
  exit 1
}

case "${TARGET_ARCH}" in
  x86|arm64|arm|riscv)
    ;;
  *)
    echo "unsupported TARGET_ARCH=${TARGET_ARCH}" >&2
    exit 1
    ;;
esac

CFLAGS=(
  -O2
  -g
  -target bpf
  "-D__TARGET_ARCH_${TARGET_ARCH}"
  -I"${ROOT}"
)

"${CLANG}" "${CFLAGS[@]}" -c "${ROOT}/nodeshield_lsm.bpf.c" -o "${OUT}/nodeshield_lsm.bpf.o"
"${CLANG}" "${CFLAGS[@]}" -c "${ROOT}/nodeshield_connect.bpf.c" -o "${OUT}/nodeshield_connect.bpf.o"

sha256sum \
  "${OUT}/nodeshield_lsm.bpf.o" \
  "${OUT}/nodeshield_connect.bpf.o" \
  > "${OUT}/SHA256SUMS"

cat > "${OUT}/manifest.json" <<EOF
{
  "schema": "koschei.nodeshield.bpf.objects.v1",
  "target_arch": "${TARGET_ARCH}",
  "objects": [
    {
      "name": "nodeshield_lsm",
      "path": "${OUT}/nodeshield_lsm.bpf.o",
      "sha256": "$(sha256sum "${OUT}/nodeshield_lsm.bpf.o" | awk '{print $1}')"
    },
    {
      "name": "nodeshield_connect",
      "path": "${OUT}/nodeshield_connect.bpf.o",
      "sha256": "$(sha256sum "${OUT}/nodeshield_connect.bpf.o" | awk '{print $1}')"
    }
  ]
}
EOF

echo "Built Node Shield BPF objects for ${TARGET_ARCH} in ${OUT}"
