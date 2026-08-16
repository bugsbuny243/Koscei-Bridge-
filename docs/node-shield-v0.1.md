# Koschei Node Shield

## Goal

Node Shield is the first compute-security product surface inside Koschei Web3. It answers two separate questions:

1. **Install time:** what authority would this workload receive if the node runs it?
2. **Runtime:** is the running artifact still behaving inside the authority boundary that was approved?

The scanner is platform-neutral. SoloHost, Docker, OCI, and future node-compute platforms should translate their native package/runtime metadata into the Node Shield types rather than duplicating security policy.

## v0.1 — install-time scanner

The install-time scanner binds a review to an immutable artifact SHA-256 and returns a deterministic `ALLOW`, `WARN`, or `BLOCK` verdict.

Current critical/high-risk checks include privileged execution, Docker socket exposure, sensitive host mounts, host namespace sharing, privilege gain, root execution, dangerous Linux capabilities, missing immutable artifact identity, and missing explicit outbound network intent.

A Docker `inspect` adapter is included as the first concrete normalizer. SoloHost-specific parsing remains an adapter boundary until Pi publishes/stabilizes the relevant package manifest/API contract.

## v0.2 — artifact-bound runtime enforcement

Runtime policy is bound to the exact reviewed artifact SHA-256. Every observed event is normalized before policy evaluation.

Runtime event classes include outbound network connection, filesystem open/write, process execution, and privilege change. Decisions are `ALLOW`, `DENY`, or `KILL`, with unknown event kinds failing closed.

### Enforcement capability contract

Every prevention-capable collector declares what it can actually enforce through `RuntimeCapabilities`:

- `observe_only`: records behavior after it occurs;
- `kill_only`: can terminate the workload after a violation;
- `pre_action_deny`: can block a covered operation before it reaches its target.

When `RequirePreAction` is enabled, Node Shield refuses to start unless the collector exposes pre-action coverage for network connect, file write, process exec, and privilege change and can bind the enforcement state to the running workload identity.

## Linux kernel enforcement

The Linux backend uses BPF LSM hooks for exec/file/credential transitions and a cgroup `connect4` program for IPv4 endpoint enforcement. Prevention is not exposed merely because the kernel supports the hooks or because BPF object files exist.

The loader requires all of the following before `pre_action_deny` may be exposed:

1. required kernel hooks are available;
2. compiled BPF objects match their expected SHA-256 digests;
3. LSM and cgroup programs load and attach successfully;
4. attachment handles can be queried and are retained for the workload lifetime;
5. the cgroup path identity matches the cgroup ID used in policy maps;
6. an independent `WorkloadIdentityVerifier` verifies that the protected runtime is the approved artifact;
7. artifact binding and policy maps are written and read back successfully.

Writing an approved digest into a kernel map is not, by itself, considered workload identity proof.

## Live kernel proof and merge gate

`scripts/nodeshield-bpf-proof.sh` is the canonical privileged proof path. It runs only after `scripts/nodeshield-bpf-readiness.sh` confirms Linux, root privileges, BPF LSM, cgroup v2, kernel BTF, clang, bpftool, Go, libbpf headers, and a successful kernel BPF feature probe.

The proof creates a disposable cgroup and a helper workload, verifies the helper executable through `/proc/<pid>/exe`, loads the verified BPF objects, and requires these outcomes:

- allowlisted network connect succeeds;
- unauthorized network connect is denied;
- filesystem write is denied;
- credential change is denied;
- new executable image is denied.

A successful run must contain the exact `TestLinuxCOREBackendKernelEnforcement` PASS marker. The proof then emits `artifacts/nodeshield-kernel-proof/kernel-proof.json`, the raw proof log, and a SHA-256 checksum for the report. The report binds the result to the repository commit, kernel release/machine, BPF target architecture, BPF manifest digest, both compiled BPF object digests, and the proof-log digest.

**Merge gate:** PR #841 must not be merged on the basis of source review alone. A compatible privileged Linux host must execute the canonical proof and produce a valid evidence artifact for the exact PR head commit. No live proof artifact means no end-to-end kernel-prevention claim and no merge.

## Security invariant

Node Shield does not trust an application because it was previously scanned. Trust is bound to:

`artifact identity + declared authority + observed behavior + enforcement capability + execution evidence`

A changed artifact is a different workload and requires a new review/policy. An enforcement adapter that cannot prove the required control surface cannot run in prevention mode.

## Next slices

1. Execute and preserve the privileged Linux kernel proof artifact for the exact PR head.
2. Fine-grained executable and filesystem allowlists rather than coarse deny gates.
3. Signed risk/evidence manifests.
4. Package-update permission diffing.
5. SoloHost adapter when the package schema/API is stable and publicly available.
6. Sentinel ingestion for cross-node anomaly and reputation analysis.
7. Verified-compute result attestation and challenge/re-execution.
