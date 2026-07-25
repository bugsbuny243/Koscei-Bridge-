# Koschei Defense OS Phase 12C — Worker Isolation Review Contract

Status: review required  
Applies to: separate Defense Worker only  
Execution gates: remain `false` until every mandatory control has independent evidence

This document defines the infrastructure evidence required before the first production-enabled LiteSVM harness run. Application flags are declarations, not proof of the external deployment boundary.

## Constitutional boundary

The worker may execute only the fixed Phase 12C command inside the pinned Bubblewrap policy. It never owns a Radar verdict and every result preserves:

```text
network_access=false
dependency_resolution=false
wallet_material_accessed=false
mainnet_rpc_accessed=false
mainnet_transaction_sent=false
verdict_authority=false
```

No review item may be waived by enabling an environment variable.

## Required deployment identity

The review package must contain:

- immutable worker image digest `sha256:<64 lowercase hex>`;
- exact deployment/service identity and environment name;
- exact Defense Worker commit SHA;
- exact migration head;
- exact worker ID;
- exact Bubblewrap, Cargo and Rust executable attestations;
- exact offline dependency inventory reference and hash;
- exact LiteSVM package/version;
- timestamped reviewer identity and review outcome.

Mutable tags, branch names and deployment labels are not acceptable image identity.

## No-egress control

Mandatory evidence:

1. outbound network is denied by the platform/container boundary;
2. DNS resolution is denied or unreachable from the execution container;
3. direct IPv4 and IPv6 egress are denied;
4. metadata endpoints and private service ranges are denied;
5. proxy variables and inherited proxy configuration are absent;
6. Bubblewrap creates a new network namespace for every harness command;
7. a controlled negative probe demonstrates that TCP, UDP, DNS and HTTP attempts cannot leave the worker;
8. the negative probe result is retained with deployment identity and image digest.

`KOSCHEI_DEFENSE_NETWORK_ISOLATED=true` is permitted only after this evidence is reviewed. The flag is not evidence by itself.

## CPU, memory, process and storage ceilings

The deployment must enforce all of the following outside the application process:

- fixed CPU quota;
- fixed memory limit with no unlimited swap escape;
- fixed process/PID ceiling;
- fixed writable ephemeral-storage limit;
- no privileged container mode;
- no host PID, IPC or network namespace;
- no host filesystem or Docker socket mount;
- no device passthrough beyond the minimal container device view;
- bounded job wall time;
- bounded stdout and stderr;
- bounded source and materialization sizes;
- process-group termination after completion, timeout or cancellation.

The review record must state the configured value for every ceiling. “Platform default” is not sufficient unless the exact default and its source are captured.

## Filesystem boundary

Mandatory evidence:

- root filesystem is read-only from the harness namespace;
- materialized source is read-only;
- `/opt/koschei/offline-deps/vendor` is read-only;
- `/opt/koschei/offline-deps/inventory.json` is read-only;
- `/opt/koschei/offline-deps/cargo-config.toml` is read-only;
- only the bounded scratch tree is writable;
- the host-side work root is private, non-symlinked and inaccessible through the sandbox root bind;
- wallet files, SSH keys, cloud credentials and application secrets are absent from all mounted paths;
- the Bubblewrap launcher is masked inside the child namespace.

A path existing in the image does not prove that it is mounted read-only; the effective Bubblewrap argv and sandbox-policy hash must be retained.

## Database permissions

The Defense Worker database role must be separate from the web/API role and restricted to the minimum required tables and operations.

Required review evidence:

- role name and grants;
- no schema ownership;
- no superuser, replication, role-management or database-creation privilege;
- no ability to modify immutable evidence tables after insert;
- no ability to disable or replace immutable triggers;
- queue claim/update permissions limited to Defense Worker job lifecycle tables;
- insert/select permissions limited to required Defense evidence tables;
- no access to unrelated customer/session/API-key/payment data;
- connection string is available only to the worker process and never to the harness environment.

Application environment filtering does not replace database-role isolation.

## Secret and wallet-material boundary

The worker process may receive only the secrets required to claim jobs and persist evidence. The harness namespace must inherit none of them.

Mandatory negative checks cover at least:

- `DATABASE_URL`;
- provider and AI API keys;
- Solana RPC URLs and credentials;
- proxy variables;
- wallet/keypair/seed material;
- cloud/platform metadata credentials;
- Git credentials and SSH agent sockets.

The fixed harness environment must be reconstructed from the immutable template and must not inherit the parent environment.

## Offline dependency evidence

Before worker readiness when Phase 12C gates are enabled, the worker must:

1. strictly decode canonical `inventory.json`;
2. reject unknown fields, trailing data and non-canonical JSON;
3. verify exact Cargo source-replacement configuration;
4. enumerate the vendor tree without following symlinks;
5. verify every path, size and SHA-256;
6. reject added, removed or changed files;
7. bind the inventory to worker ID and immutable image digest;
8. persist immutable inventory evidence;
9. re-run the same verification before every source launch;
10. compare the materialized `Cargo.toml` and `Cargo.lock` hashes with the approved inventory.

There is no runtime `cargo fetch`, `cargo update`, `cargo vendor`, Git dependency, registry update or network fallback.

## Reference execution acceptance

Production enablement also requires one owner-approved reference harness executed twice under the exact same:

- profile hash;
- materialization hash;
- worker image digest;
- executable hashes;
- dependency inventory hash;
- sandbox-policy hash;
- command hash;
- environment hash;
- input hash.

Acceptance requires:

- both attempts complete under bounds;
- both attempts retain `network_access=false` and `dependency_resolution=false`;
- identical stdout/stderr hashes when deterministic output is expected;
- identical deterministic result hash;
- different attempt identities are allowed and expected;
- no result is promoted to exploitability, asset-impact, proof-of-fix or safety evidence.

A failed or unavailable reference run keeps all production execution gates disabled.

## Reviewer decision record

The final review record must explicitly state one outcome:

- `APPROVED_FOR_BOUNDED_REFERENCE_RUN`;
- `BLOCKED_CONFIGURATION_MISMATCH`;
- `BLOCKED_MISSING_EVIDENCE`;
- `BLOCKED_EXTERNAL_ISOLATION_UNVERIFIED`.

Only the first outcome permits a bounded reference run. It does not authorize general production execution or change any Koschei verdict.
