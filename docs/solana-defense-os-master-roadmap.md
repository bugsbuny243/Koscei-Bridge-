# Koschei Solana Defense Intelligence OS — Master Roadmap

This document is the durable implementation order for the Defense OS track. It preserves the constitutional boundary that Defense evidence may support investigation but never owns a Koschei Radar verdict.

## Constitutional boundary

- imported source is never executed by the web/API process;
- no Defense path stores wallet, keypair, seed phrase or signing material;
- no Defense path submits a mainnet transaction;
- AI may explain or propose but cannot create evidence, alter a grade, approve a patch or claim proof-of-fix;
- missing, malformed, stale or mismatched evidence fails closed;
- every Defense result preserves `verdict_authority=false`.

## Completed phases

### Phase 1 — Read-Only Defense Agent Runtime

Bounded read-only source/IDL/bytecode intake and deterministic evidence-first analysis.

Status: **complete**.

### Phase 2 — Immutable Artifact Intake

Versioned source, IDL and bytecode artifacts with hashes, provenance and immutable persistence.

Status: **complete**.

### Phase 3 — Program Security Lab

Program graph, static finding hypotheses and explicit evidence/limitation separation.

Status: **complete**.

### Phase 4 — Local Verification and Review-Only Repair

Allowlisted local verification commands and review-only patch proposals without deployment authority.

Status: **complete**.

### Phase 5 — Benchmark and Learning Flywheel

Immutable findings, reproduction evidence and versioned learning records without verdict authority.

Status: **complete**.

### Phase 6 — Deployed Bytecode Verification

Program deployment and bytecode evidence with explicit source-equivalence boundaries.

Status: **complete**.

### Phase 7 — Exact-Commit GitHub Source Import

Bounded public source import pinned to one exact commit SHA.

Status: **complete**.

### Phase 8 — Separate Defense Worker

Queue, lease recovery and isolated worker process separation from the web/API service.

Status: **complete**.

### Phase 9 — Baseline/Patched Paired Reproduction

Exact baseline and patched artifact comparison under identical fixtures and invariants. This phase remains the proof-of-fix authority.

Status: **complete**.

### Phase 10 — Program Deployment Sentinel

Deployment/ProgramData/authority change monitoring and explicit invalidation of inherited assumptions.

Status: **complete**.

### Phase 11 — Anchor Harness Planner and Toolchain Attestation

Deterministic non-executable harness plans derived from Anchor IDLs, human-confirmation invariant templates and immutable worker toolchain probes.

Every Phase 11 plan remains:

```text
execution_ready=false
manual_guidance_required=true
verdict_authority=false
```

Status: **complete**.

### Phase 12A — Pinned Toolchain + Fail-Closed Execution Profile

Exact executable SHA-256 evidence, immutable worker-image binding, owner-confirmed invariants, fixed LiteSVM/Trident command policies, immutable ready/blocked profiles, stale-image rejection and execution-time binary rehash authorization.

Phase 12A exposes no harness execution action.

Status: **complete**.

### Phase 12B — Deterministic Offline Harness Materialization

Phase 12B consumes one ready LiteSVM profile and its owner-prepared immutable harness bundle. It produces a second normalized immutable artifact without downloading dependencies or executing source.

Delivered:

1. root `Cargo.toml` and immutable `Cargo.lock` validation;
2. direct LiteSVM dependency and matching lock-package evidence;
3. Git and escaping path-dependency rejection;
4. deterministic path/text normalization;
5. raw SHA-256 for every normalized file, Cargo manifest and Cargo lock;
6. timestamp-free `koschei/materialization.json`;
7. immutable `source_bundle` with `artifact_role=materialized_harness`;
8. immutable migration-backed materialization evidence;
9. explicit no-network/no-execution/no-verdict-authority flags.

Status: **complete**.

## Active phase

### Phase 12C — First Isolated Deterministic LiteSVM Run

Phase 12C may consume only a Phase 12A-authorized LiteSVM profile and its exact Phase 12B `materialized_harness` artifact.

The current implementation requires:

1. live worker ID and immutable image digest match;
2. execution-time re-resolution and SHA-256 verification for Cargo, Rust and Bubblewrap;
3. a pinned Bubblewrap policy with new network/PID/IPC/UTS/user namespaces;
4. read-only root and source input;
5. one bounded writable scratch mount;
6. cleared environment and fixed variables only;
7. fixed argv `cargo test --locked --offline`, launched without a shell;
8. process-group timeout/cancellation cleanup;
9. bounded stdout/stderr and immutable result evidence;
10. explicit `network_access=false`, `mainnet_transaction_sent=false` and `verdict_authority=false`.

The worker image currently installs Bubblewrap, but the Phase 12C execution gates remain false by default. Production enablement also requires a separately reviewed no-egress/container resource policy and immutable offline dependency-cache policy.

Status: **in progress**.

## Planned phases after Phase 12

### Phase 13 — Stateful Adversarial Sequence Engine

Pinned Trident or equivalent stateful fuzzing, bounded sequence grammars, deterministic seeds, corpus retention and reproducible crash/minimal-sequence evidence.

### Phase 14 — Reachability and Asset-Impact Proof Layer

Bind a static finding to a concrete instruction path, controlled account state and measurable unauthorized state or asset delta. Capability alone is not exploitability.

### Phase 15 — Differential Patch Verification

Run exact baseline and patched programs against the same immutable fixtures, seeds and invariants. A patch must remove the target failure without violating accepted invariants.

### Phase 16 — Continuous Program Defense

Sentinel changes may queue bounded re-analysis and approved regression suites. Deployment changes never silently inherit prior proof.

### Phase 17 — Human Review and Release Governance

Review queues, evidence signing, separation of duties, approval thresholds and explicit export of a technical security dossier. Koschei still does not deploy patches.
