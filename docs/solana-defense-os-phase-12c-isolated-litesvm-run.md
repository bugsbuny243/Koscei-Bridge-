# Koschei Solana Defense Intelligence OS — Phase 12C

Status: implementation in progress  
Base: `main@28f1505e5943a65a960eb9c13cfaed95b7d6d8c5`  
Actor contract: `ACTOR_INVESTIGATION_ENGINE.md` v1.0  
Unified Radar ruleset: `koschei-unified-radar-rules-v1.0.0`

Phase 12C performs the first isolated deterministic LiteSVM harness command run. It consumes only evidence already accepted by Phase 12A and Phase 12B.

## Canonical investigation boundary

Applicable `ACTOR_INVESTIGATION_ENGINE.md` rules:

- §1 question 10 — missing, malformed, stale or mismatched execution evidence remains unavailable;
- §3 — toolchain, worker, materialization, sandbox and runtime mismatches fail closed;
- §4 — every technical result retains exact artifact, executable, sandbox-policy and SHA-256 references;
- §5 — Defense OS execution evidence has `verdict_authority=false`.

The signed deterministic Koschei investigation verdict remains the only verdict authority. A Phase 12C run cannot change a Radar grade, verdict signature or rule result.

## Explicit scope

Phase 12C may:

- enqueue one fixed `litesvm` harness execution action;
- consume one Phase 12A execution profile with `readiness_status=ready` and `execution_allowed=true`;
- consume the exact Phase 12B immutable artifact with `artifact_role=materialized_harness`;
- run only inside the separate Defense Worker;
- re-authorize live worker identity, image digest, Cargo, Rust and Bubblewrap executable SHA-256 immediately before launch;
- launch only the pinned Bubblewrap executable from the worker process;
- execute logical argv `cargo test --locked --offline` only as Bubblewrap's fixed final command;
- use new network/PID/IPC/UTS/user namespaces, a cleared environment, read-only root/source and one writable scratch mount;
- enforce profile wall-time/output limits and process-group cleanup;
- persist one immutable attempt record for success, failure, timeout, cancellation or rejection.

## Explicit non-scope

This phase does not:

- download, resolve, update or vendor dependencies;
- run `cargo fetch`, `cargo update` or any network fallback;
- accept caller-supplied commands, arguments, replacements or environment values;
- launch Cargo or imported source directly from the web/API process;
- launch untrusted source directly in the host worker namespace;
- use wallet, keypair, seed phrase or signing material;
- access mainnet RPC;
- submit any transaction;
- run Trident or stateful fuzzing;
- prove exploitability, reachability, asset impact, source-to-deployment equivalence, proof-of-fix or program safety;
- apply or deploy a patch.

Every response and persisted result preserves:

```text
network_access=false
dependency_resolution=false
wallet_material_accessed=false
mainnet_rpc_accessed=false
mainnet_transaction_sent=false
verdict_authority=false
```

## Feature gates

All gates remain false by default:

```text
KOSCHEI_DEFENSE_HARNESS_EXECUTION_ENABLED=false
KOSCHEI_DEFENSE_LITESVM_EXECUTION_ENABLED=false
KOSCHEI_DEFENSE_WORKER_ENABLED=false
KOSCHEI_DEFENSE_SANDBOX_ENABLED=false
KOSCHEI_DEFENSE_NETWORK_ISOLATED=false
```

The API may enqueue only when both Phase 12C execution gates and the existing worker-queue gate are explicitly true. The separate worker additionally requires its worker/sandbox gates, a valid immutable worker-image digest and operator-confirmed no-egress deployment evidence.

`KOSCHEI_DEFENSE_NETWORK_ISOLATED=true` is defense-in-depth evidence for the deployment boundary. It is not treated as proof by itself. Each command also runs in a Bubblewrap-created network namespace, and every result retains the external-infrastructure limitation.

No implementation PR enables these variables in production.

## Required inputs

One execution request binds exactly:

- `profile_ref` — immutable Phase 12A profile;
- `materialization_ref` — immutable Phase 12B materialization;
- `materialized_artifact_ref` — exact immutable source bundle;
- `worker_id` — must equal the profile worker;
- `worker_image_digest` — must equal the profile and live worker image;
- fixed action `run_litesvm_harness`.

The materialization must match the profile by:

- profile reference and profile hash;
- program ID and network;
- source harness artifact reference and hash;
- command policy;
- engine `litesvm`;
- Cargo manifest and lock hashes;
- materialized bundle hash;
- generated `koschei/materialization.json` contents.

A mismatch is rejected and no source command is launched. Once enough immutable identity exists, a rejected launch attempt is persisted rather than promoted into a program finding.

## Mandatory runtime authorization

Immediately before command launch, the Defense Worker must:

1. call the existing `AuthorizeHarnessExecution` boundary for the profile's pinned Cargo/Rust tools;
2. load the latest pinned Bubblewrap attestation for the same worker and image;
3. resolve Cargo, Rust and Bubblewrap again from the live worker filesystem;
4. require the resolved paths to equal the attested paths;
5. recompute each executable SHA-256;
6. require every live hash to equal the immutable attestation.

Any mismatch fails closed before source execution.

## Pinned Bubblewrap sandbox policy

The deterministic policy version is:

```text
koschei-bwrap-litesvm-v1
```

Its canonical properties are persisted as JSON and SHA-256 evidence:

- `--unshare-all`;
- `--die-with-parent`;
- `--new-session`;
- read-only host root;
- new `/proc` and `/dev` mounts;
- ephemeral `/tmp`, `/run` and `/var/tmp`;
- cleared process environment;
- read-only materialized source at `/tmp/koschei-workspace`;
- writable scratch only at `/tmp/koschei-scratch`;
- working directory `/tmp/koschei-workspace`;
- no inherited parent environment;
- no shell;
- fixed final Cargo argv.

Before mounting any source, the worker performs a bounded Bubblewrap namespace preflight. Failure to create the namespace is persisted as `rejected` with `source_executed=false`.

The actual process started by the worker is Bubblewrap, not Cargo. Cargo is the final command inside the new namespace. Bubblewrap setup errors are distinguished from test/program failures and remain sandbox evidence rather than program findings.

## Fixed logical command and environment

The only logical Phase 12C command is:

```text
cargo test --locked --offline
```

It is represented as a fixed argv vector and is never interpreted by a shell.

The environment is an explicit allowlist. It:

- fixes locale, timezone, terminal and source-date values;
- excludes database, provider, RPC, proxy, deployment and wallet variables;
- points writable Cargo/Rust/target/temp state only into `/tmp/koschei-scratch`;
- binds the persisted environment hash to the exact template and pinned tool paths;
- sets `CARGO_NET_OFFLINE=true`;
- preserves no caller-provided values.

The persisted record contains an environment hash, sandbox-policy hash and executable evidence; it does not persist secrets.

A worker image lacking packages required by the immutable lock file may fail with `dependency_unavailable_offline`. This is explicit unavailable evidence and never causes a network fallback. A successful reference run requires a separately reviewed immutable image-baked dependency/cache policy before execution gates are enabled.

## Remaining infrastructure boundary

Bubblewrap provides per-job namespace and filesystem isolation, but the production worker still needs independently reviewed container/deployment controls for:

- outbound network denial outside the application claim;
- CPU and memory ceilings;
- writable storage/quota ceilings;
- immutable image identity;
- no secret or wallet injection;
- restricted service/database permissions;
- incident shutdown and rollback.

Phase 12C stays draft/default-off until these controls and the immutable offline dependency policy are accepted.

## Immutable attempt record

Migration `081_defense_litesvm_execution_attempts.sql`:

- permits pinned `bwrap` toolchain attestations;
- prevents duplicate active LiteSVM jobs for one deterministic request hash;
- creates the append-only execution-attempt store.

Each attempt contains:

- attempt reference and schema version;
- request/job reference and attempt number;
- profile reference and hash;
- materialization reference and hash;
- source/materialized artifact references and hashes;
- program ID and network;
- worker ID and image digest;
- Cargo, Rust and Bubblewrap attestation/executable evidence;
- fixed command argv and command hash;
- complete sandbox policy and sandbox-policy hash;
- environment hash;
- input/Cargo manifest/Cargo lock hashes;
- configured budgets;
- start/completion timestamps and duration;
- status `rejected`, `completed`, `failed`, `timed_out` or `cancelled`;
- exit code and termination reason;
- bounded stdout/stderr and raw SHA-256 values;
- truncation flags;
- evidence references and limitations;
- explicit no-network/no-wallet/no-mainnet flags;
- deterministic result hash;
- `verdict_authority=false`.

Rows are immutable through the existing Defense OS mutation-rejection trigger.

Repeated runs are separate immutable attempts, while identical evidence and output produce the same deterministic result hash because attempt identity, timestamps and duration are excluded from that hash payload.

## Worker queue integration

The existing `verify_bundle` worker action remains unchanged.

Phase 12C adds:

```text
run_litesvm_harness
```

The action accepts only profile/materialization references. It accepts no commands, replacements, finding reference, patch reference or environment payload.

The request hash is deterministic over immutable input references and the fixed action. A PostgreSQL partial unique index prevents duplicate queued/running jobs while permitting a deliberate rerun after a terminal state.

The web/API process may enqueue and read status only. The sole command-launch boundary is `ExecuteLiteSVMWorkerJob` in the separate Defense Worker.

## Owner API

Owner-only:

```text
GET|POST /api/owner/defense/litesvm-execution
```

POST body:

```json
{
  "action": "enqueue",
  "profile_ref": "KHEP1-...",
  "materialization_ref": "KHM1-..."
}
```

The decoder rejects unknown fields, oversized bodies and multiple JSON values. The endpoint never executes synchronously and always returns explicit no-mainnet/no-verdict-authority flags.

## Current implementation slice

Implemented on the draft branch:

- migration 081 immutable attempt and pinned-Bubblewrap evidence schema;
- deterministic active-job idempotency;
- strict fixed-action owner/queue validation;
- exact profile/materialization/artifact/file/Cargo hash checks;
- execution-time Cargo/Rust/Bubblewrap path and SHA-256 re-authorization;
- deterministic Bubblewrap sandbox policy and hash;
- bounded no-source namespace preflight;
- direct pinned-Bubblewrap launch with fixed Cargo argv inside the namespace;
- cleared environment, read-only source and bounded scratch;
- process-group timeout/cancellation cleanup;
- bounded stdout/stderr and deterministic hashes;
- immutable result persistence and repeatable result hash;
- default-off web/worker gates;
- focused fail-closed tests;
- Bubblewrap installation in the Defense Worker image.

Unrelated ARVIS, auth, entitlement, alert, Radar, Transaction Guard and legacy verification paths are not refactored.

## Required validation

Before ready-for-review:

1. PostgreSQL 17 migration chain through 081;
2. immutable attempt mutation rejection;
3. ready profile and exact materialization accepted;
4. blocked/mismatched/stale evidence rejected before source launch;
5. Cargo/Rust/Bubblewrap path or SHA mutation rejected;
6. Bubblewrap namespace preflight failure persisted as pre-source rejection;
7. caller command/environment injection impossible;
8. fixed argv contains no shell;
9. offline dependency absence classified without network fallback;
10. timeout/cancellation kills the process group;
11. stdout/stderr bounds and hashes deterministic;
12. success/non-zero/rejected result rows immutable;
13. duplicate active enqueue idempotent;
14. lease recovery cannot execute one attempt concurrently twice;
15. API process cannot launch source;
16. complete `go test ./...`;
17. `go vet ./...`;
18. Linux builds for API, Defense Worker and Defense Sentinel;
19. public JavaScript and Turkish-copy checks when touched;
20. gitleaks;
21. govulncheck;
22. high-severity/high-confidence gosec gate.

## Completion rule

Phase 12C is complete only after:

- code, migration, tests and documentation are merged;
- all required CI gates pass;
- migration 081 deploys with execution gates off;
- the immutable worker image, no-egress/resource policy and offline dependency policy are reviewed;
- one owner-approved reference harness runs in the isolated worker;
- a second run produces the same deterministic result hash for identical inputs and outputs;
- no mainnet, wallet or verdict-authority boundary is weakened.
