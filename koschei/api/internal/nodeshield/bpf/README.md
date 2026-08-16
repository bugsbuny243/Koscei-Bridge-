# Node Shield BPF programs

This directory contains the Linux kernel-enforcement sources for Koschei Node Shield.

## Objects

- `nodeshield_lsm.bpf.c` — BPF LSM gates for executable-image changes, write-capable file opens, and credential-change attempts.
- `nodeshield_connect.bpf.c` — cgroup `connect4` gate using an exact IPv4 endpoint allowlist per protected cgroup.

These sources do **not** make Node Shield prevention-capable by merely existing or compiling.

## Build and provenance

Run:

```bash
TARGET_ARCH=x86 bash ./build.sh
```

Supported target identifiers are `x86`, `arm64`, `arm`, and `riscv`.

The build emits:

- `out/nodeshield_lsm.bpf.o`
- `out/nodeshield_connect.bpf.o`
- `out/SHA256SUMS`
- `out/manifest.json`

The manifest schema is `koschei.nodeshield.bpf.objects.v1`. Each compiled object is bound to SHA-256, and the Go loader path verifies every object digest before privileged loading is allowed.

## Prevention invariant

`pre_action_deny` may only be exposed after all of the following are true:

1. the required BPF LSM and cgroup BPF hooks are available;
2. compiled BPF object digests match the approved manifest;
3. all required LSM programs are attached;
4. the cgroup connect program is attached to the intended cgroup;
5. policy maps are initialized;
6. policy state is bound to the approved artifact/workload identity.

If any condition is false, prevention mode must fail closed.

## Current boundary

The BPF source, object build script, SHA-256 manifest verification, loader contract, platform gating, and prevention-state validation exist. A production privileged backend that loads CO-RE objects and returns verified attachment state is still required before live kernel prevention can be claimed.

The first LSM object uses coarse cgroup gates for exec/file/credential changes. Fine-grained executable and file policy maps are still required before those controls can be described as production-grade allowlisting. The network object models an exact IPv4 endpoint allowlist per cgroup; IPv6 and DNS lifecycle handling remain follow-up work.
