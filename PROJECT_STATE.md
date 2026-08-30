# Koschei Web3 Project State

This file is the repository checkpoint for continuing Koschei Web3 work across chat/session boundaries. Repository state wins over conversational assumptions.

## CURRENT STATE

- Active product PR: **none**.
- Current verified `main` head: `fcfe3e754954e4682d30982c027ee1bc48478d53` (PR **#966**, `fix(actor): repair legacy transaction evidence normalization`).
- Latest verified customer-product merge remains PR **#962**, `feat(customer): add Professional state witness recheck`, merge commit `e2a0fff1f2730c3862f9679659e82ed6aa586a59`.
- PR #966 repaired an Actor/ARVIS evidence-integrity defect without introducing a parallel decision engine or changing signing/broadcast authority.
- Immutable Solana transaction evidence from `solana_jsonparsed_instruction` and `solana_transaction_logs` now has the enforced meaning **one evidence key = one chain observation**; rescans/replays must not manufacture recurrence by inflating `occurrence_count`.
- Snapshot/event evidence keeps its legitimate recurrence semantics; PR #966 deliberately did not flatten those counts.
- Migration prefix `102` is now recorded as an accepted historical gap. `103` and all later migration filenames remain unchanged because complete filenames are applied migration identities.
- Professional Transaction Preflight remains the metered pre-sign decision.
- Professional State Recheck remains the immediate entitlement-only continuation for the same signing decision and does **not** consume a second SaaS output.
- State Recheck reuses the existing fail-closed `TransactionGuardStateRecheck` engine and never signs or broadcasts a transaction.
- A positive continuation still requires a successful HTTP response with both `ok: true` and `safe_to_proceed: true`; every other result requires withholding the prior preflight decision.
- Retired legacy asset/KOSCH authorization remains outside the active commercial boot chain. Paid product access is SaaS-entitlement based, with Paddle as the current billing path.
- Canonical OpenAPI represents **154 registered API paths**.
- `main` remains unprotected; exact-head and exact-merge-candidate discipline is still required.

## CHANGED

### Actor transaction evidence integrity — PR #966

Root cause found in historical migration `081_actor_transaction_evidence_idempotency.sql`:

- the steady-state transaction-evidence count-preservation trigger was installed before the one-time historical normalization update;
- that trigger correctly blocked future replay inflation, but it also prevented already-inflated immutable transaction rows from being repaired to `occurrence_count = 1`.

Forward-only repair:

- added `118_actor_transaction_evidence_legacy_normalization.sql`; migration 081 was **not** rewritten;
- migration 118 seeds a temporary legacy-shaped probe with `occurrence_count = 7`;
- inside the migration transaction, only `zz_security_actor_transaction_evidence_idempotency` is temporarily dropped;
- only immutable transaction evidence sources are normalized to `occurrence_count = 1`;
- the migration asserts that no immutable transaction row remains inflated;
- the canonical preservation trigger is restored;
- a repeated conflict/upsert probe proves the same evidence key remains at count `1`;
- the temporary probe is deleted before commit.

### Migration-history hygiene discovered by PR #966

The first PR run exposed an older baseline inconsistency: `103_tradepi_agent_persistence.sql` entered repository history on 2026-08-27 while its immediately preceding tree already had `101_paddle_saas_billing_v1.sql` and no `102_*.sql`.

Because the migration runner keys applied history by complete filename, renaming `103` to `102` or fabricating a new `102` migration would rewrite/reuse deployed history. The safe correction therefore:

- added `102` to `migration-numbering-baseline.json` as an accepted historical gap;
- documented the history in `docs/migration-numbering-hygiene.md`;
- preserved `103` and all later migration identities unchanged.

### Repository branch classification update

The branch names `fix/actor-transaction-evidence-idempotency` and `fix/actor-transaction-evidence-legacy-normalization` may still exist as refs, but their relevant capability/debt is no longer unresolved:

- the original idempotency capability was previously merged;
- the legacy-normalization defect discovered during review is now repaired and merged by PR #966.

Treat both as **merged-history cleanup candidates**, not as missing product capability. Do not revive either branch as a new feature line.

The following remain unresolved and require current-`main` comparison before deletion or revival:

- `fix/actor-acceptance-coverage-semantics`
- `fix/actor-verdict-evidence-integrity`
- `fix/customer-capability-labels-v2`
- `fix/helius-token-metadata-free-first-v1` (PR #912 is closed unmerged; explicit supersession has not yet been proven)

## VERIFIED

### PR #966 exact head

Verified PR head: `9cd15717d3c4f56039e8554f18d9c38317010d57`.

All triggered PR workflows completed successfully, including:

- Migration Numbering and its deliberate duplicate/gap failure tests;
- full PostgreSQL 17 migration application including migration 118;
- retention hash/archive/resume/checksum fail-closed checks;
- immutable dossier storage verification;
- full `go test ./...`;
- Go race-test consolidation packages;
- `go vet ./...`;
- Linux `go build ./...`;
- secret scanning, reachable vulnerability scanning, high-confidence static security scanning;
- CodeQL and Supply Chain Security;
- Auth Freeze Guard;
- Persistent Actor Memory Acceptance;
- Funding Cluster Memory / Outcome / Trajectory acceptances;
- Public Product Smoke;
- Operator Exit Corpus PostgreSQL acceptance;
- exact synthetic merge-candidate verification;
- target-base freshness assertion.

No open PR review threads or PR comments remained before merge.

### Merged main head

PR #966 merged as `fcfe3e754954e4682d30982c027ee1bc48478d53`.

The actual merged `main` head triggered **10 push workflows; all 10 completed successfully with 0 failures**. The push verification again covered migration numbering, PostgreSQL migration execution, retention/archive checks, immutable dossier validation, public contract checks, full tests, vet, build, secret/vulnerability/static security gates, and product/actor acceptance surfaces.

## BROKEN / MISSING

- No known CI blocker remains on verified `main` head `fcfe3e754954e4682d30982c027ee1bc48478d53`.
- No known blocker remains for the merged Actor transaction-evidence normalization repair.
- `main` remains unprotected, so correctness still depends on exact-head discipline rather than GitHub branch-protection enforcement.
- Historical branches are not fully classified. Deleting or reviving them blindly can discard unique work or reintroduce obsolete architecture.
- `fix/actor-acceptance-coverage-semantics` and `fix/actor-verdict-evidence-integrity` still require current-main semantic comparison.
- PR #912 / `fix/helius-token-metadata-free-first-v1` remains closed unmerged and unresolved until current-main containment or explicit supersession is proven.
- State Recheck reduces the time-of-check/time-of-signing window but cannot prove chain state remains unchanged after final observation and before network execution.

## WORK-IN-PROGRESS POLICY

1. Keep **one active product PR** at a time.
2. When no product PR is active, perform repo-state / hygiene inspection before selecting another feature.
3. A CI failure does **not** justify a new feature branch by itself; classify the failure first.
4. New ideas go to backlog and do not interrupt the current production slice.
5. A stale branch or old PR is not a product requirement. Compare it with current `main` and preserve only capability that is genuinely missing.
6. Do not merge stale cleanup or feature branches whose final diff no longer matches current architecture or product scope.
7. Validate the exact synthetic merge candidate against the current target head and re-check the actual merged `main` head.
8. Never rewrite an already-applied migration merely to repair numbering or historical behavior; use a forward migration and preserve filename identity.
9. Chat history is context only; this repository checkpoint plus current GitHub state is authoritative.

## NEXT

1. **Do not open an unrelated product feature PR yet.**
2. Continue repository hygiene from verified `main` `fcfe3e754954e4682d30982c027ee1bc48478d53`.
3. Resolve `fix/actor-acceptance-coverage-semantics` against current `main`: determine whether its semantics are already present, safely superseded, or genuinely missing.
4. Then resolve `fix/actor-verdict-evidence-integrity` with the same evidence standard.
5. Classify `fix/customer-capability-labels-v2` and PR #912 / `fix/helius-token-metadata-free-first-v1` before deleting or reviving them.
6. Treat `fix/actor-transaction-evidence-idempotency` and `fix/actor-transaction-evidence-legacy-normalization` as merged-history cleanup candidates; do not revive their old diffs.
7. After remaining branch hygiene stabilizes, inspect live `main` and choose exactly one smallest customer-useful Web3 production gap from current code/evidence.
8. Keep Transaction Preflight / State Recheck and ARVIS evidence-first behavior as the current decision line; do not fork a parallel risk-score or stale actor engine.

## DO NOT START

- No unrelated product feature while the remaining repository-hygiene ambiguities are unresolved.
- No Koschei Lang or Sentinel implementation inside this repository; define external integration contracts only when needed.
- No revival of retired KOSCH/asset-based authorization or retired manual payment runtime.
- No revival of stale defense-validation, ARVIS, agent, or scanner branches without a current-main diff proving the capability is still missing.
- No fake scores, fake chain data, placeholder enterprise capabilities, or disconnected demo surfaces.

## RISKS

- **Repository bloat / stale branches:** historical refs can create false signals about what is active or missing.
- **Unprotected main:** parallel writes can move the target outside branch-protection enforcement.
- **Over-cleanup risk:** squash-merged and superseded branches may appear diverged even when their capability is already integrated; exact PR lineage/current-main comparison is required before deletion.
- **Unique-work risk:** remaining actor/evidence branches may still contain real unmerged semantics, so bulk deletion remains unsafe.
- **Evidence inflation risk:** future ingestion paths must preserve the distinction between immutable transaction evidence and legitimate recurring snapshot/event evidence.
- **Migration-history risk:** accepted historical gaps, including `102`, must remain empty; applied filenames must not be renumbered or reused.
- **Fresh-state limitation:** State Recheck proves only the bounded state observed during that recheck, not future state after observation.
