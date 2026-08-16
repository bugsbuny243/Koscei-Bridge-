# Koschei Node Shield

## Goal

Node Shield is the first compute-security product surface inside Koschei Web3. It answers two separate questions:

1. **Install time:** what authority would this workload receive if the node runs it?
2. **Runtime:** is the running artifact still behaving inside the authority boundary that was approved?

The scanner is platform-neutral. SoloHost, Docker, OCI, and future node-compute platforms should translate native package/runtime metadata into Node Shield types rather than duplicating security policy.

## Install-time scanner

The scanner binds a review to an immutable artifact SHA-256 and returns deterministic `ALLOW`, `WARN`, or `BLOCK` verdicts. Current critical/high-risk checks include privileged execution, Docker socket exposure, sensitive host mounts, host namespace sharing, dangerous Linux capabilities, privilege gain, root execution, missing immutable artifact identity, and missing explicit outbound-network intent.

A Docker `inspect` adapter is the first concrete normalizer. SoloHost-specific parsing remains an adapter boundary until Pi publishes/stabilizes the relevant package manifest/API contract.

## Runtime enforcement

Runtime policy is bound to the exact reviewed artifact SHA-256. Normalized event classes cover outbound network connections, filesystem write/open behavior, process execution, and privilege change.

Decisions are `ALLOW`, `DENY`, and `KILL`. A changed artifact, forbidden privilege change, undeclared destination/write/child executable, or unknown event fails closed according to policy.

### Enforcement capability contract

Collectors/enforcers must declare what they can truly enforce:

- `observe_only` — telemetry only; never a prevention claim;
- `kill_only` — can terminate after a violation;
- `pre_action_deny` — can reject a covered operation before completion.

When pre-action enforcement is required, Node Shield refuses to start unless artifact identity plus network connect, file write, process exec, and privilege-change controls are all covered.

## Linux CO-RE enforcement

The Linux path now contains BPF LSM programs for exec/file/credential gates and a cgroup `connect4` program for exact IPv4 endpoint allowlisting. CO-RE objects are built with clang, hashed into a SHA-256 manifest, re-verified by Go before privileged load, attached with `cilium/ebpf`, and retained by workload-scoped link handles.

BPF object existence or hook availability is never enough to claim prevention. Full prevention state requires:

1. expected BPF object digests match;
2. target cgroup directory identity matches the cgroup ID used by policy maps;
3. an independent `WorkloadIdentityVerifier` proves the target cgroup belongs to the reviewed workload/artifact;
4. all required LSM and cgroup links attach and expose valid link information;
5. artifact/policy maps initialize successfully;
6. the approved artifact SHA-256 is written to and read back from kernel policy state;
7. all required pre-action boundaries remain covered.

Writing an approved hash into a BPF map is **not** identity verification. The production loader refuses to arm a workload gate without an independent identity verifier.

## Privileged kernel proof

`linux_core_integration_test.go` is guarded by the `nodeshield_integration` build tag. It creates a disposable cgroup, starts a helper process, moves that PID into the protected cgroup, and verifies `/proc/<pid>/exe` SHA-256 against the approved artifact before arming kernel policy.

The live proof then requires:

- an allowlisted IPv4 endpoint remains reachable;
- a second listening but unauthorized endpoint is blocked;
- a forbidden file write is blocked;
- a credential change is blocked;
- a new executable image is blocked.

`.github/workflows/node-shield-kernel-ci.yml` provides two validation tiers. Pull requests run normal Go unit/vet/compile checks on GitHub-hosted Linux. The live kernel proof is manual and requires a self-hosted runner labeled `nodeshield-bpf` with root access, cgroup v2, kernel BTF, BPF LSM, clang, bpftool, and libbpf headers.

Until the privileged kernel proof succeeds on a compatible runner, Koschei must **not** claim end-to-end live kernel prevention.

## Current CI status

The feature branch currently has no recorded GitHub Actions runs. The connected GitHub integration can read workflow/run state but cannot read repository Actions permission settings. Therefore PR #841 remains unmerged until executable validation is available.

## Security invariant

Node Shield trust is bound to:

`artifact identity + independent workload identity + declared authority + observed behavior + verified enforcement capability`

A changed artifact is a different workload and requires a new review/policy. A kernel hook, map value, container label, or collector assertion is never sufficient by itself to elevate trust.

## Next slices

1. Execute the privileged BPF integration proof on a compatible runner and fix every verifier/kernel mismatch it reveals.
2. Add signed risk/evidence manifests for successful enforcement sessions.
3. Add package-update permission diffing.
4. Add a SoloHost adapter only when Pi's package schema/API is stable and public.
5. Feed cross-node behavior and enforcement evidence into Koschei Sentinel.
6. Extend verified-compute result attestation and challenge/re-execution.
