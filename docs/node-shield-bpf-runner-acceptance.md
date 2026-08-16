# Node Shield BPF runner acceptance checklist

A host is eligible to execute the merge-gating kernel proof only when all checks below pass.

- Same-repository PR only; never privileged execution from forks.
- Exact PR head SHA checkout verified before loading BPF.
- Linux BPF LSM enabled.
- cgroup v2 writable.
- kernel BTF available at `/sys/kernel/btf/vmlinux`.
- `clang`, `bpftool`, Go 1.25.12, and libbpf headers available.
- Runner labels include `self-hosted`, `linux`, `nodeshield-bpf`.
- `scripts/nodeshield-bpf-readiness.sh` passes as root.
- `scripts/nodeshield-bpf-proof.sh` is the only accepted proof entry point.
- Evidence checksum validates.
- Evidence commit SHA equals the exact PR head.
- Evidence records PASS for `TestLinuxCOREBackendKernelEnforcement`.

A Railway/container test, compile-only result, or BPF object build does not satisfy this checklist.
