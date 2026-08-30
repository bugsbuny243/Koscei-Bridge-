# Koschei Web3 Project State

This file is the repository checkpoint for continuing Koschei Web3 work across chat/session boundaries. Repository state wins over conversational assumptions.

## CURRENT STATE

- Active product PR: **none**.
- Current verified `main` head: `fcfe3e754954e4682d30982c027ee1bc48478d53`, merged by PR **#966**, `fix(actor): repair legacy transaction evidence normalization`.
- Latest verified product merge: PR **#962**, `feat(customer): add Professional state witness recheck`.
- Verified product merge commit: `e2a0fff1f2730c3862f9679659e82ed6aa586a59`.
- Previous verified maintenance merge: PR **#963**, `fix(ci): remove retired payment runtime references`.
- PR #966 repaired an Actor/ARVIS evidence-integrity defect without introducing a parallel decision engine or changing signing/broadcast authority.
- Immutable Solana transaction evidence from `solana_jsonparsed_instruction` and `solana_transaction_logs` now enforces **one evidence key = one chain observation**; rescans/replays must not manufacture recurrence by inflating `occurrence_count`.
- Snapshot/event evidence retains its legitimate recurrence semantics; PR #966 deliberately did not flatten those counts.
- Migration prefix `102` is recorded as an accepted historical gap. `103` and all later migration filenames remain unchanged because complete filenames are applied migration identities.
- The documentation checkpoint immediately preceding the latest evidence-integrity work merged as `fcda934cd5405b868617e5c95fdc0ee57aec45c9`.
- Repository hygiene previously removed **11 proven-safe historical branch refs**; no product code was changed by those deletions.
- Professional Transaction Preflight remains the metered pre-sign decision.
- Professional State Recheck remains the immediate entitlement-only continuation and does **not** consume a second SaaS output for the same signing decision.
- State Recheck reuses the existing fail-closed `TransactionGuardStateRecheck` engine and never signs or broadcasts a transaction.
- A positive continuation requires a successful HTTP response with both `ok: true` and `safe_to_proceed: true`; every other result requires withholding the prior preflight decision.
- Retired legacy asset/KOSCH authorization remains outside the active commercial boot chain. Paid product access is SaaS-entitlement based, with Paddle as the current billing path.
- The entitlement schema is migration-owned; retired request-time payment schema bootstrap is not restored.
- Canonical OpenAPI represents **154 registered API paths**.
- `main` remains unprotected.
- Historical unprotected branches remain numerous and must not be revived or deleted without comparison against current `main` and/or exact PR lineage evidence.

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

The first PR run also exposed an older migration-numbering baseline inconsistency: `103_tradepi_agent_persistence.sql` entered repository history on 2026-08-27 while its immediately preceding tree already had `101_paddle_saas_billing_v1.sql` and no `102_*.sql`.

Because the migration runner keys applied history by complete filename, renaming `103` to `102` or fabricating a new `102` migration would rewrite/reuse deployed history. The safe correction therefore:

- added `102` to `migration-numbering-baseline.json` as an accepted historical gap;
- documented the history in `docs/migration-numbering-hygiene.md`;
- preserved `103` and all later migration identities unchanged.

The branch refs `fix/actor-transaction-evidence-idempotency` and `fix/actor-transaction-evidence-legacy-normalization` may still exist, but their relevant capability/debt is no longer unresolved. Treat them as **merged-history cleanup candidates**, not as missing product capability, and do not revive their old diffs.

### Professional State Recheck — PR #962

- Added `POST /api/customer/web3/transaction-state-recheck` for Professional customers.
- Kept Transaction Preflight metered while State Recheck uses Professional entitlement-only access.
- Recheck is exposed only for ALLOW preflights with a complete state witness and a state-bound v2/v3 enforcement permit.
- Recheck requires the exact transaction/network/witness bound by the permit and rereads only the bounded witnessed account set.
- Customer requests reuse `KoscheiAuth`; permit/witness material remains transient in page memory.
- Added PostgreSQL-backed abuse controls and the required OpenAPI request contract.
- OpenAPI documents the actual fail-closed 409 expired-permit and 503 unavailable/incomplete-evidence behavior.

### Retired legacy access cleanup

- Removed retired compatibility routes and their compatibility tombstone handler from the active server boot chain.
- Removed obsolete production-evidence fixture tests whose underlying retired snapshot had already been deleted.
- Preserved generic verdict-synchronization and customer-analysis tests.
- Regenerated the OpenAPI contract to 154 registered paths.

### Retired payment runtime repair — PR #963

A later direct-main cleanup left dangling references to already-retired payment runtime code. PR #963 repaired that regression without reviving the old authorization/payment path:

- Removed dead owner wrappers that still referenced `OwnerPaymentRequestsList`, `OwnerApprovePaymentRequest`, and `OwnerRejectPaymentRequest`.
- Removed the retired `ensurePaymentSchema` dependency from `ensureOwnerSchema`.
- Removed the same retired schema dependency from customer package status.
- Kept package status on the existing `entitlements` data model and preserved unavailable/fail-closed behavior when the database query cannot be served.
- Verified that `entitlements` is migration-owned (`001_entitlements_customer_id_nullable.sql` plus later Paddle billing migrations); no retired request-time bootstrap was restored.
- Repaired a pre-existing final-newline/gofmt drift in `internal/openapi/generator.go` introduced by the preceding direct-main KOSCH classifier cleanup. The OpenAPI generator content was otherwise unchanged by that formatting repair.

### Repository hygiene continuation — 2026-08-30

No product code was modified. Eleven historical refs were removed only after fail-closed lineage checks proved them safe to delete:

- `fix/retired-payment-runtime-references`
- `docs/project-state-20260829-retired-payment-repair`
- `fix/customer-saas-surface-truth-v1`
- `fix/dossier-saas-entitlement-v1`
- `fix/dossier-registry-autopublish`
- `fix/customer-capability-labels-v3`
- `fix/history-saas-entitlement-v1`
- `fix/customer-investigation-ui-rpc-resilience`
- `fix/customer-radar-502`
- `fix/arvis-social-render-v2`
- `fix/auth-cors-retention-20260710`

The cleanup deliberately preserved branches that still contain unique/unresolved work or lack sufficient supersession proof. After PR #966, the following remain classified as **unresolved / do not delete yet**:

- `fix/actor-acceptance-coverage-semantics`
- `fix/actor-verdict-evidence-integrity`
- `fix/customer-capability-labels-v2`
- `fix/helius-token-metadata-free-first-v1` (PR #912 is closed unmerged; no supersession proof has yet been established)

`fix/actor-transaction-evidence-idempotency` is no longer in the unresolved capability set; the original capability was merged previously and its remaining legacy normalization defect was repaired by PR #966.

## VERIFIED

### PR #966 — Actor transaction evidence integrity

Final PR head `9cd15717d3c4f56039e8554f18d9c38317010d57` passed all triggered PR workflows. Verification included:

- Migration Numbering and deliberate duplicate/gap failure tests;
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

PR #966 merged as `fcfe3e754954e4682d30982c027ee1bc48478d53`. The actual merged `main` head then triggered **10 push workflows; all 10 completed successfully with 0 failures**. Push verification again covered migration numbering, PostgreSQL migration execution, retention/archive checks, immutable dossier validation, public contract checks, full tests, vet, build, secret/vulnerability/static security gates, and product/actor acceptance surfaces.

### PR #962

Final PR head `6a10f08f6469bf17760bf79eca105e1361429b07` passed all permanent PR workflows triggered for that head. After merge, actual product head `e2a0fff1f2730c3862f9679659e82ed6aa586a59` completed 9/9 push workflows successfully.

### Retired access cleanup

The exact-head cleanup candidate passed focused handler/http/openapi tests, OpenAPI generation check with 154 registered paths, `git diff --check`, and full `go test ./...`. Verified main head `34d0a8823b17a91c033a0495d3de6235ab69b949` then completed 8/8 push workflows successfully.

### PR #963

Final PR head `2035036be76d7854c3a286db455014cf1269e62b` passed **9/9 PR workflows**:

- API Required CI
- Release Gates Verification
- Operator Exit Corpus Acceptance
- Security CI
- CodeQL
- Supply Chain Security
- OpenAPI Contract
- Public Product Smoke
- Auth Freeze Guard

The final PR verification included PostgreSQL migration and retention checks, immutable dossier storage verification, public JavaScript/language/investigation contract checks, full Go tests, vet, build, secret scanning, reachable vulnerability scanning, static security scanning, exact merge-candidate verification, and target-base freshness.

PR #963 merged as `90d318ae4242d38383f96ffa33db86e734246c60`. The actual merged `main` head then triggered **7 push workflows; all 7 completed successfully with 0 failures**. API Required CI on the merged head completed migrations, retention checks, immutable dossier validation, public JS/language contracts, Go tests, vet, build, secret scanning, vulnerability scanning, and static security scanning successfully.

### Repository hygiene continuation

Three temporary, helper-only cleanup workflows ran from exact refs and self-deleted after success; none was merged into `main`:

- run `33284921118`: verified the two target branches were ancestors/fully contained before deleting `fix/retired-payment-runtime-references` and `docs/project-state-20260829-retired-payment-repair`.
- run `33285040682`: completed successfully after checking exact remote SHAs plus merged-PR or explicit supersession state; deleted `fix/customer-saas-surface-truth-v1`, `fix/dossier-saas-entitlement-v1`, `fix/dossier-registry-autopublish`, and the closed-unmerged-but-explicitly-replaced `fix/customer-capability-labels-v3`.
- run `33285211818`: completed successfully after checking exact remote SHAs and exact merged PR heads; deleted `fix/history-saas-entitlement-v1` (PR #898), `fix/customer-investigation-ui-rpc-resilience` (PR #621), `fix/customer-radar-502` (PR #620), `fix/arvis-social-render-v2` (PR #747), and `fix/auth-cors-retention-20260710` (PR #540).

Post-run branch searches confirmed the deleted refs and temporary helper refs are absent. `main` remained at `df00c4f29e261fa838e9fccc0f3c32cc238cdcb0` throughout those hygiene executions.

## BROKEN / MISSING

- No known CI blocker remains on verified `main` head `fcfe3e754954e4682d30982c027ee1bc48478d53`.
- No known blocker remains for the merged Professional State Recheck slice.
- No known blocker remains for the merged Actor transaction-evidence normalization repair.
- `main` remains unprotected, so correctness still depends on exact-head discipline rather than GitHub branch-protection enforcement.
- Historical branches are not fully classified. Deleting or reviving them blindly could discard unique work or reintroduce obsolete architecture.
- `fix/actor-acceptance-coverage-semantics` and `fix/actor-verdict-evidence-integrity` still require current-main semantic comparison before any deletion or revival decision.
- PR #912 / `fix/helius-token-metadata-free-first-v1` is closed unmerged and remains unresolved until a current-main comparison or explicit supersession record proves what happened to that capability.
- State Recheck reduces the time-of-check/time-of-signing window but cannot prove chain state will remain unchanged after the final observation and before network execution.

## WORK-IN-PROGRESS POLICY

1. Keep **one active product PR** at a time.
2. When no product PR is active, perform repo-state / hygiene inspection before selecting another feature.
3. A CI failure does **not** justify a new feature branch or product PR by itself; classify the failure first.
4. New ideas go to backlog and do not interrupt the current production slice.
5. A stale branch or old PR is not a product requirement. Compare it to current `main` first and preserve only capability that is still genuinely missing.
6. Do not merge stale cleanup or feature branches whose final diff no longer matches current architecture or product scope.
7. Validate the exact synthetic merge candidate against the current target head and re-check the actual merged `main` head.
8. Temporary repair workflows/scripts must be removed before final merge.
9. Never rewrite an already-applied migration merely to repair numbering or historical behavior; use a forward migration and preserve filename identity.
10. Chat history is context only; this repository checkpoint plus current GitHub state is authoritative.

## NEXT

1. **Do not open a new unrelated product feature PR yet.**
2. Continue repository hygiene from verified `main` `fcfe3e754954e4682d30982c027ee1bc48478d53`, using exact branch SHA + merged/superseded PR evidence or current-main containment as the deletion boundary.
3. Resolve `fix/actor-acceptance-coverage-semantics` against current `main`: determine whether its semantics are already present, safely superseded, or genuinely missing.
4. Then resolve `fix/actor-verdict-evidence-integrity` with the same evidence standard.
5. Resolve `fix/customer-capability-labels-v2` and PR #912 / `fix/helius-token-metadata-free-first-v1` before deleting or reviving them.
6. Treat `fix/actor-transaction-evidence-idempotency` and `fix/actor-transaction-evidence-legacy-normalization` as merged-history cleanup candidates; do not revive their old diffs.
7. Delete only refs proven safe to remove; preserve genuinely unique capability as backlog/integration evidence instead of reviving stale architecture wholesale.
8. After branch hygiene reaches a stable checkpoint, inspect live `main` and choose exactly one smallest customer-useful Web3 production gap from current code/evidence.
9. Keep Transaction Preflight / State Recheck and ARVIS evidence-first behavior as the current decision line; do not fork a parallel decision engine from stale work.

## DO NOT START

- No unrelated product feature while repository hygiene is unresolved.
- No Koschei Lang or Sentinel implementation inside this repository; define external integration contracts when needed.
- No revival of retired KOSCH/asset-based authorization or retired manual payment runtime.
- No revival of stale defense-validation, ARVIS, agent, or scanner branches without a current-main diff proving the capability is still missing.
- No fake scores, fake chain data, placeholder enterprise capabilities, or disconnected demo surfaces.

## RISKS

- **Repository bloat / stale branches:** historical refs can create false signals about what is active or missing.
- **Unprotected main:** parallel writes can move the target outside branch-protection enforcement.
- **Over-cleanup risk:** squash-merged and superseded branches may appear diverged even when their capability is already integrated; exact PR lineage is required before deletion.
- **Unique-work risk:** some actor/evidence branches still contain real unmerged diffs, so bulk deletion remains unsafe.
- **Evidence inflation risk:** future ingestion paths must preserve the distinction between immutable transaction evidence and legitimate recurring snapshot/event evidence.
- **Migration-history risk:** accepted historical gaps, including `102`, must remain empty; applied filenames must not be renumbered or reused.
- **Retired-runtime regression risk:** future cleanup must search for callers and schema dependencies before deleting implementation files; compile success alone is not enough.
- **Rate policy tuning:** State Recheck is currently bounded by 30/min per IP and 12/min per verified customer; changes must remain evidence-driven and bounded-cost.
- **Fresh-state limitation:** State Recheck proves only the bounded state observed during that recheck, not future state after observation.
