# Koschei Web3 Project State

This file is the repository checkpoint for continuing Koschei Web3 work across chat/session boundaries. Repository state wins over conversational assumptions.

## CURRENT STATE

- Active product PR: **none**.
- Open pull requests: **none** at this checkpoint.
- Latest verified product merge: PR **#962**, `feat(customer): add Professional state witness recheck`.
- Verified product merge commit: `e2a0fff1f2730c3862f9679659e82ed6aa586a59`.
- Professional Transaction Preflight is the metered pre-sign decision.
- Professional State Recheck is the immediate entitlement-only continuation and does **not** consume a second SaaS output for the same signing decision.
- State Recheck reuses the existing fail-closed `TransactionGuardStateRecheck` engine and never signs or broadcasts a transaction.
- A customer receives a positive continuation only when the recheck HTTP response succeeds and reports both `ok: true` and `safe_to_proceed: true`; every other result requires withholding the prior preflight decision.
- `main` is still not branch-protected.
- The repository still contains many historical unprotected branches. They are not evidence of active work and must not be revived without comparing them against current `main`.

## CHANGED

PR #962 added and hardened the customer-facing State Recheck path:

- Added `POST /api/customer/web3/transaction-state-recheck` for Professional customers.
- Kept Transaction Preflight metered while State Recheck uses Professional entitlement-only access.
- Exposes recheck only for ALLOW preflights with a complete state witness and a state-bound v2/v3 enforcement permit.
- Recheck requires the exact transaction/network/witness bound by the permit and rereads only the bounded witnessed account set.
- Customer requests reuse `KoscheiAuth`; auth initialization is awaited once so a valid Neon session can restore a missing or expired local JWT.
- Recheck permit/witness material remains transient in page memory; raw recheck transaction text is cleared after use.
- `pagehide` and persisted `pageshow` invalidate the recheck UI so browser back-forward cache cannot restore a dead actionable control.
- Added shared PostgreSQL-backed abuse controls: 30 requests/minute per client IP and 12 requests/minute per verified customer subject before upstream RPC / Evidence Court work.
- Added a dedicated required OpenAPI State Recheck request contract for `permit_token`, `transaction`, and `state_witness`; `network` defaults to `solana-mainnet`.
- OpenAPI documents actual fail-closed 409 expired-permit and 503 unavailable/incomplete-evidence responses.
- Fixed the pre-existing pricing-policy verifier drift.
- All ten inline review findings raised during #962 were fixed and resolved before merge.

## VERIFIED

Focused verification for the final bounded State Recheck fixes passed:

- `node scripts/verify-customer-state-recheck-v1.js`
- `node scripts/verify-customer-transaction-preflight-v1.js`
- `node scripts/verify-customer-transaction-preflight-ui-v1.js`
- `go test ./internal/http ./internal/handlers ./internal/openapi -count=1`
- `go run ./cmd/openapi-gen -check`
- `git diff --check`

Final PR head `6a10f08f6469bf17760bf79eca105e1361429b07` then passed all permanent PR workflows triggered for that head, including API Required CI, Release Gates Verification, Operator Exit Corpus Acceptance, Security CI, CodeQL, Supply Chain Security, OpenAPI Contract, Pricing Policy V2 Acceptance, Public Product Smoke, Enterprise API Keys V1 Acceptance, Watchlist Evidence-State V2 Acceptance, Customer Investigation UX V2 Acceptance, Canonical Investigation History V1 Acceptance, Owner Growth Console Acceptance, and Auth Freeze Guard.

The Operator Exit gate completed both exact synthetic merge-candidate verification and target-base freshness successfully before merge.

After merge, actual `main` product head `e2a0fff1f2730c3862f9679659e82ed6aa586a59` triggered **9** push workflows; all 9 completed successfully. API Required CI on the actual merged head completed migrations, JavaScript/language contracts, tests, vet, build, secret scan, reachable vulnerability scan, and high-confidence static security scan successfully.

## BROKEN / MISSING

- No known blocker remains for the merged Professional State Recheck slice.
- `main` remains unprotected, so repository correctness still depends on current-head merge discipline rather than GitHub branch protection.
- Historical branches are numerous and currently unclassified. Deleting or reviving them blindly could either discard unique work or reintroduce obsolete architecture.
- The merged recheck reduces the time-of-check/time-of-signing window but cannot prove that chain state will remain unchanged after the final observation and before network execution.

## WORK-IN-PROGRESS POLICY

1. Keep **one active product PR** at a time.
2. When no product PR is active, perform repo-state / hygiene inspection before selecting another feature.
3. A CI failure does **not** justify a new branch or PR by itself; classify the failure first.
4. New ideas go to backlog and do not interrupt the current production slice.
5. A stale branch or old PR is not a product requirement. Compare it to current `main` first and preserve only capability that is still genuinely missing.
6. Do not merge stale cleanup or feature branches whose final diff no longer matches current architecture or product scope.
7. Validate the exact synthetic merge candidate against the current target head and re-check the actual merged `main` head.
8. Temporary repair workflows/scripts must be removed before final merge.
9. Chat history is context only; this repository checkpoint plus current GitHub state is authoritative.

## NEXT

1. **Do not open a new product PR yet.**
2. Perform repository hygiene on the historical branch set: classify each candidate as already-merged, obsolete/superseded, or containing unique unmerged capability.
3. Delete/close only branches proven safe to remove; do not use branch age or name alone as evidence.
4. After branch hygiene, inspect current `main` and choose exactly one smallest customer-useful Web3 production gap from live code/evidence.
5. Keep Transaction Preflight / State Recheck and ARVIS evidence-first behavior as the current product line; do not fork a parallel decision engine from stale work.

## DO NOT START

- No unrelated product feature while repository hygiene is unresolved.
- No Sentinel or Koschei Lang implementation in this repository.
- No revival of stale defense-validation, ARVIS, agent, or scanner branches without a current-main diff proving the capability is still missing.
- No fake scores, fake chain data, placeholder enterprise capabilities, or disconnected demo surfaces.

## RISKS

- **Repository bloat / stale branches:** many historical branches can create false signals about what is active or missing.
- **Unprotected main:** parallel writes can still move the target outside GitHub branch-protection enforcement.
- **Rate policy tuning:** the current State Recheck abuse boundary is 30/min per IP and 12/min per verified customer; production traffic may justify tuning, but changes must remain evidence-driven and must not remove the bounded-cost property.
- **Fresh-state limitation:** State Recheck proves only the bounded state observed during that recheck, not future state after the observation.
