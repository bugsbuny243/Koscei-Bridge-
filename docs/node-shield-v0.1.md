# Koschei Node Shield

## Goal

Node Shield is the first compute-security product surface inside Koschei Web3. It answers two separate questions:

1. **Install time:** what authority would this workload receive if the node runs it?
2. **Runtime:** is the running artifact still behaving inside the authority boundary that was approved?

The scanner is platform-neutral. SoloHost, Docker, OCI, and future node-compute platforms should translate their native package/runtime metadata into the Node Shield types rather than duplicating security policy.

## v0.1 — install-time scanner

The install-time scanner binds a review to an immutable artifact SHA-256 and returns a deterministic `ALLOW`, `WARN`, or `BLOCK` verdict.

Current critical/high-risk checks include:

- privileged container execution;
- Docker daemon socket exposure;
- sensitive host filesystem mounts;
- host PID/IPC/network namespace sharing;
- privilege gain;
- root execution;
- dangerous Linux capabilities;
- missing immutable artifact identity;
- missing explicit outbound network intent.

A Docker `inspect` adapter is included as the first concrete normalizer. SoloHost-specific parsing remains an adapter boundary until Pi publishes/stabilizes the relevant package manifest/API contract.

## v0.2 — artifact-bound runtime enforcement

Runtime policy is bound to the exact reviewed artifact SHA-256. Every observed event is normalized before policy evaluation.

Current normalized runtime event classes:

- outbound network connection;
- filesystem open/write;
- process execution;
- privilege change.

Current enforcement decisions:

- `ALLOW`: behavior remains inside the approved boundary;
- `DENY`: the individual operation must not proceed;
- `KILL`: the workload crossed a trust boundary and the supervisor should terminate it.

Fail-closed rules currently include:

- running artifact hash differs from the approved artifact -> `KILL`;
- forbidden privilege change -> `KILL`;
- undeclared outbound destination -> `DENY`;
- undeclared filesystem write -> `DENY`;
- undeclared child executable -> `DENY`;
- unknown future event kind -> `DENY`.

The runtime evaluator is deliberately collector-agnostic. A Docker/eBPF/SoloHost collector converts native events to `RuntimeEvent`; policy evaluation stays in the common core. Collectors are not trusted to authorize behavior: they only report observations. Authorization remains deterministic inside Node Shield.

A runtime `DENY` is only meaningful when a supervisor can actually prevent the operation. Until a collector/supervisor is wired to kernel/container enforcement, the evaluator is a policy decision engine rather than a complete containment boundary. Koschei must never market observation-only mode as prevention.

## Security invariant

Node Shield does not trust an application because it was previously scanned. Trust is bound to:

`artifact identity + declared authority + observed behavior`

A changed artifact is a different workload and requires a new review/policy.

## Validation

Node Shield lives under `koschei/api/**`, so the repository's existing **API Required CI** workflow covers pull-request changes to this package. That workflow runs Go tests, vet, build, and database-backed API checks before merge.

## Next slices

1. Runtime event collector/supervisor integration.
2. Signed risk/evidence manifests.
3. Package-update permission diffing.
4. SoloHost adapter when the package schema/API is stable and publicly available.
5. Sentinel ingestion for cross-node anomaly and reputation analysis.
6. Verified-compute result attestation and challenge/re-execution.
