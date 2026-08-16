# Node Shield BPF programs

This directory contains the first kernel-enforcement sources for Koschei Node Shield.

## Objects

- `nodeshield_lsm.bpf.c` — BPF LSM gates for executable-image changes, write-capable file opens, and credential-change attempts.
- `nodeshield_connect.bpf.c` — cgroup `connect4` gate using an exact IPv4 endpoint allowlist per protected cgroup.

These sources do **not** make Node Shield prevention-capable by merely existing or compiling. The Go-side `LinuxBPFProbe` only advertises `pre_action_deny` after all of the following are true:

1. the kernel exposes the required BPF LSM and cgroup BPF hooks;
2. the compiled program objects are verified against an expected digest;
3. all required programs are attached to the intended hooks/cgroup;
4. policy maps are initialized and bound to the approved artifact/workload identity.

If any condition is false, prevention mode must fail closed.

## Build shape

The intended build is CO-RE based and requires a generated `vmlinux.h` for the target kernel build environment plus libbpf headers. A typical build pipeline will compile each source with clang's BPF target and then hash the resulting object before it is accepted by the loader.

The loader and object-digest manifest are deliberately a separate slice. Until they are implemented and validated on a compatible Linux runner, this directory is kernel-source groundwork rather than a production prevention claim.

## Current policy granularity

The first LSM object uses coarse cgroup gates for exec/file/credential changes. Fine-grained executable and file policy maps are still required before those controls can be described as production-grade allowlisting. The network object already models an exact IPv4 endpoint allowlist per cgroup; IPv6 and DNS lifecycle handling remain follow-up work.
