# Koschei Defense OS — Phase 12C Offline Dependency Policy

Status: implementation contract  
Stacked base: `feat/defense-os-phase-12c-isolated-litesvm-run@466685711d9a2b0755143a554f1908606b1b4bff`  
Tracked readiness gate: issue #662  
Actor contract: `ACTOR_INVESTIGATION_ENGINE.md` v1.0  
Unified Radar ruleset: `koschei-unified-radar-rules-v1.0.0`

## 1. Decision

Phase 12C uses an **image-baked, read-only Cargo vendor store**. Runtime dependency downloads, mutable registry caches and host-provided Cargo state are forbidden.

The immutable worker image contains:

```text
/opt/koschei/offline-deps/
  cargo-config.toml
  inventory.json
  vendor/
```

The image build may resolve dependencies only while producing a reviewed immutable image. The running Defense Worker may not resolve, fetch, update or download dependencies.

The alternative model—embedding a complete vendor tree in every owner harness artifact—is not selected for Phase 12C because it duplicates a large dependency tree per materialization and expands the owner-controlled source surface. A future version may support that model only through a separate versioned policy.

## 2. Constitutional boundary

Every implementation preserves:

```text
network_access=false
dependency_resolution=false
wallet_material_accessed=false
mainnet_rpc_accessed=false
mainnet_transaction_sent=false
verdict_authority=false
```

The dependency inventory is technical execution evidence only. It cannot create a Radar rule, grade, verdict, exploitability claim, proof-of-fix claim or program-safety claim.

Missing, malformed, stale, mismatched or incomplete dependency evidence fails closed before imported source is launched.

## 3. Build-time contract

The Defense Worker image build must use an exact reference dependency specification:

- exact `Cargo.toml` bytes and SHA-256;
- exact `Cargo.lock` bytes and SHA-256;
- direct `litesvm = "=0.6.1"` dependency for the first reference profile;
- `cargo vendor --locked --versioned-dirs` or a semantically equivalent pinned Cargo operation;
- no Git dependency;
- no path dependency outside the immutable build input;
- no mutable branch, tag or floating semver range;
- no dependency resolution during the runtime image stage.

The vendor tree is copied into the final worker image as read-only content owned by root. The runtime worker remains an unprivileged user and cannot modify the inventory, Cargo configuration or vendor tree.

The Docker build produces timestamp-free `inventory.json` with canonical path ordering.

## 4. Canonical inventory

`inventory.json` contains:

- schema version;
- policy version;
- exact Cargo manifest SHA-256;
- exact Cargo lock SHA-256;
- Cargo vendor configuration SHA-256;
- direct LiteSVM package name and exact version;
- complete sorted file inventory;
- for every file: relative path, byte length and raw SHA-256;
- file count and total bytes;
- deterministic vendor-tree SHA-256;
- explicit `network_access=false` and `dependency_resolution=false` runtime boundaries;
- no timestamps, image tags, database IDs or deployment-generated values.

Canonical identity:

```text
dependency_inventory_hash = SHA-256(canonical inventory payload)
```

The immutable worker image digest and the inventory hash remain separate evidence. Both must match the Phase 12C authorization record.

## 5. Runtime authorization

Immediately before source launch, the separate Defense Worker must:

1. require every Phase 12C feature gate already enforced by PR #661;
2. re-authorize worker ID and immutable image digest;
3. load `/opt/koschei/offline-deps/inventory.json` through a fixed absolute path;
4. reject symlinks, path traversal, duplicate paths and non-canonical entries;
5. recompute the SHA-256 and byte length for every inventory file;
6. recompute the deterministic vendor-tree hash;
7. require the materialized harness `Cargo.lock` hash to equal the approved inventory lock hash;
8. require the direct LiteSVM version in materialization evidence to equal the approved inventory package version;
9. require the fixed Cargo source-replacement configuration hash;
10. persist the inventory reference/hash, lock hash, file count, total bytes and worker image digest in the immutable execution attempt;
11. reject before Bubblewrap launch on any mismatch.

No runtime path may run:

```text
cargo fetch
cargo update
cargo vendor
git
curl
wget
```

## 6. Sandbox mount contract

Bubblewrap mounts:

- materialized harness input read-only at `/tmp/koschei-workspace`;
- bounded scratch read-write at `/tmp/koschei-scratch`;
- approved vendor tree read-only at `/opt/koschei/offline-deps/vendor`;
- approved Cargo source-replacement configuration read-only at a fixed path.

The runtime environment uses a new scratch `CARGO_HOME`, but Cargo is directed to the approved vendor source through the fixed configuration. No parent Cargo home, registry cache, Git checkout or user configuration is inherited.

The logical command remains exactly:

```text
cargo test --locked --offline
```

## 7. Persistent evidence

A follow-up migration adds an immutable dependency-inventory evidence record containing at least:

- inventory reference and version;
- worker ID;
- worker image digest;
- fixed inventory path;
- Cargo manifest hash;
- Cargo lock hash;
- Cargo config hash;
- LiteSVM package/version;
- file manifest;
- file count;
- total bytes;
- vendor-tree hash;
- inventory hash;
- evidence status and limitations;
- `network_access=false`;
- `dependency_resolution=false`;
- `verdict_authority=false`;
- observation time for the worker attestation record.

The inventory payload itself remains timestamp-free. Observation time is stored outside deterministic identity.

Phase 12C execution attempts additionally retain the exact inventory reference and hash used for that attempt.

## 8. Fail-closed taxonomy

Stable rejection reasons include:

- `dependency_inventory_unavailable`;
- `dependency_inventory_malformed`;
- `dependency_inventory_path_escape`;
- `dependency_inventory_file_missing`;
- `dependency_inventory_file_mismatch`;
- `dependency_inventory_hash_mismatch`;
- `dependency_inventory_image_mismatch`;
- `dependency_lock_mismatch`;
- `dependency_litesvm_version_mismatch`;
- `dependency_cargo_config_mismatch`;
- `dependency_store_not_read_only`;
- `dependency_unavailable_offline`.

None of these states is a program finding. They are unavailable execution evidence.

## 9. Required tests

Before this policy may be accepted:

1. deterministic inventory generation from identical vendor trees;
2. order-independent filesystem enumeration with canonical sorted identity;
3. changed byte, added file, removed file and duplicate-path rejection;
4. symlink and path-escape rejection;
5. mismatched image digest rejection;
6. mismatched Cargo manifest and Cargo lock rejection;
7. mismatched LiteSVM version rejection;
8. mutable Git/path dependency rejection remains enforced;
9. Cargo source-replacement configuration hash verification;
10. read-only vendor mount evidence;
11. no parent Cargo/registry/Git environment inheritance;
12. missing dependency produces explicit unavailable evidence with no network fallback;
13. immutable database record mutation rejection;
14. identical image/inventory/materialization produces identical dependency evidence hash;
15. complete PostgreSQL migration chain;
16. complete `go test ./...`;
17. `go vet ./...`;
18. Linux builds for API, Defense Worker and Sentinel;
19. gitleaks, govulncheck and high-confidence gosec.

## 10. Deployment boundary

This policy does not prove Railway or another platform blocks egress. Production readiness separately requires independently reviewed deployment controls for:

- outbound network denial;
- non-root runtime identity;
- immutable image digest;
- CPU, memory, process and writable-storage ceilings;
- no provider, RPC or wallet secrets injected into the worker;
- restricted database permissions;
- private `KOSCHEI_DEFENSE_WORK_ROOT` mount;
- tested Bubblewrap namespace support;
- shutdown, rollback and incident-disable procedure.

All Phase 12C execution gates remain false until both this immutable dependency policy and the external worker-isolation checklist are accepted.

## 11. Completion rule

This policy is complete only when:

- the image build creates the canonical vendor inventory;
- runtime authorization recomputes and verifies it before source launch;
- immutable evidence is persisted and linked to each attempt;
- negative tests prove every mismatch fails before Bubblewrap launches source;
- one owner-approved reference harness completes twice with the same deterministic result hash;
- no network, wallet, mainnet or verdict-authority boundary is weakened.
