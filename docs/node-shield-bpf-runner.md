# Node Shield privileged BPF runner

This runner exists for one purpose: execute the live Node Shield kernel-enforcement proof before the feature may be merged or advertised as end-to-end prevention.

## Trust boundary

The privileged proof MUST NOT execute code from fork pull requests. The workflow permits the self-hosted job only when all of the following are true:

- the event is a pull request from this same repository;
- the PR has the `nodeshield-kernel-proof` label; or the workflow is manually dispatched after the workflow exists on the default branch;
- the checkout HEAD equals the exact PR head SHA expected by the workflow;
- the canonical readiness and proof scripts pass.

Do not broaden this condition to arbitrary pull requests. The job runs with root/kernel privileges.

## Required runner properties

The host must provide:

- Linux with BPF LSM enabled;
- writable cgroup v2;
- `/sys/kernel/btf/vmlinux`;
- root privileges for the proof job;
- `clang` with BPF target support;
- `bpftool`;
- libbpf development headers under `/usr/include/bpf`;
- Go 1.25.12 support;
- a GitHub self-hosted runner carrying the labels `self-hosted`, `linux`, and `nodeshield-bpf`.

Before registration/use, run:

```bash
sudo ./scripts/nodeshield-bpf-readiness.sh
```

A host that fails readiness is not a valid proof host.

## Canonical proof

The only accepted live proof entry point is:

```bash
sudo -E ./scripts/nodeshield-bpf-proof.sh
```

The script builds fresh CO-RE BPF objects from the checked-out source, creates the object digest manifest, runs `TestLinuxCOREBackendKernelEnforcement`, verifies the exact test PASS marker, and emits a tamper-evident evidence bundle.

Expected evidence directory:

```text
artifacts/nodeshield-kernel-proof/
  kernel-proof.json
  kernel-proof.log
  kernel-proof.json.sha256
```

The evidence must bind at minimum:

- exact Git commit SHA;
- kernel release and architecture;
- BPF object and manifest SHA-256 values;
- raw proof-log SHA-256;
- `TestLinuxCOREBackendKernelEnforcement`;
- result `PASS`.

## Live enforcement assertions

The proof is accepted only if the protected helper workload demonstrates all of these on the actual kernel:

- explicitly allowed IPv4 endpoint connection succeeds;
- unauthorized IPv4 endpoint connection is denied;
- forbidden filesystem write is denied;
- forbidden credential/setuid transition is denied;
- forbidden new executable image is denied;
- incorrect cgroup identity, artifact identity, incomplete loader state, or tampered BPF object fails closed in the surrounding test suite.

## Merge gate

Do not merge Node Shield kernel prevention based on source review, unit tests, Railway/container tests, or successful BPF compilation alone.

Merge requires a valid evidence artifact produced from the exact PR head on a compatible privileged Linux host.
