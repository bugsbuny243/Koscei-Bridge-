# Koschei Web3 Project State

This file is the repository checkpoint for continuing Koschei Web3 work across chat/session boundaries. Repository state wins over conversational assumptions.

## CURRENT STATE

- Active product PR: **none**.
- Latest verified product merge: PR **#962**, `feat(customer): add Professional state witness recheck`.
- Verified product merge commit: `e2a0fff1f2730c3862f9679659e82ed6aa586a59`.
- Latest verified maintenance merge: PR **#963**, `fix(ci): remove retired payment runtime references`.
- Last code-affecting verified `main` head before this documentation checkpoint: `90d318ae4242d38383f96ffa33db86e734246c60`.
- Professional Transaction Preflight remains the metered pre-sign decision.
- Professional State Recheck remains the immediate entitlement-only continuation and does **not** consume a second SaaS output for the same signing decision.
- State Recheck reuses the existing fail-closed `TransactionGuardStateRecheck` engine and never signs or broadcasts a transaction.
- A positive continuation requires a successful HTTP response with both `ok: true` and `safe_to_proceed: true`; every other result requires withholding the prior preflight decision.
- Retired legacy asset/KOSCH authorization remains outside the active commercial boot chain. Paid product access is SaaS-entitlement based, with Paddle as the current billing path.
- The entitlement schema is migration-owned; retired request-time payment schema bootstrap is not restored.
- Canonical OpenAPI represents **154 registered API paths**.
- `main` remains unprotected.
- Historical unprotected branches remain numerous and must not be revived or deleted without comparison against current `main`.

## CHANGED

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

## VERIFIED

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

## BROKEN / MISSING

- No known CI blocker remains on verified maintenance head `90d318ae4242d38383f96ffa33db86e734246c60`.
- No known blocker remains for the merged Professional State Recheck slice.
- `main` remains unprotected, so correctness still depends on exact-head discipline rather than GitHub branch-protection enforcement.
- Historical branches are not fully classified. Deleting or reviving them blindly could discard unique work or reintroduce obsolete architecture.
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
9. Chat history is context only; this repository checkpoint plus current GitHub state is authoritative.

## NEXT

1. **Do not open a new product feature PR yet.**
2. Resume repository hygiene from the current verified `main`.
3. Classify historical branch candidates as already-contained, obsolete/superseded, or containing unique unmerged capability.
4. Delete only refs proven safe to remove; branch age or name alone is not evidence.
5. After branch hygiene reaches a stable checkpoint, inspect live `main` and choose exactly one smallest customer-useful Web3 production gap from current code/evidence.
6. Keep Transaction Preflight / State Recheck and ARVIS evidence-first behavior as the current decision line; do not fork a parallel decision engine from stale work.

## DO NOT START

- No unrelated product feature while repository hygiene is unresolved.
- No Koschei Lang or Sentinel implementation inside this repository; define external integration contracts when needed.
- No revival of retired KOSCH/asset-based authorization or retired manual payment runtime.
- No revival of stale defense-validation, ARVIS, agent, or scanner branches without a current-main diff proving the capability is still missing.
- No fake scores, fake chain data, placeholder enterprise capabilities, or disconnected demo surfaces.

## RISKS

- **Repository bloat / stale branches:** historical refs can create false signals about what is active or missing.
- **Unprotected main:** parallel writes can move the target outside branch-protection enforcement.
- **Retired-runtime regression risk:** future cleanup must search for callers and schema dependencies before deleting implementation files; compile success alone is not enough.
- **Rate policy tuning:** State Recheck is currently bounded by 30/min per IP and 12/min per verified customer; changes must remain evidence-driven and bounded-cost.
- **Fresh-state limitation:** State Recheck proves only the bounded state observed during that recheck, not future state after observation.
