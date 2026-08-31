# Koschei Web3 Project State

This file is the authoritative repository checkpoint for continuing Koschei Web3 work across chat/session boundaries. Current repository state wins over conversational assumptions and stale branch history.

## CURRENT STATE

- Active maintenance PR: **#975 — `chore: retire Paddle billing surface`**.
- PR #975 branch: `chore/remove-paddle`.
- Current verified `main` head: **`163471aea13b7cd4671fe62f152b585b2e6ab468`**, merged by PR **#968**, `fix(actor): bind dominant holder reuse to canonical evidence`.
- PR #968 binds ARD-C002 dominant-holder reuse to canonical `dominant_holder_of` evidence and requires distinct-mint evidence coverage before the rule may remain grade-changing.
- Missing, partial, same-mint, unverified, or keyless holder evidence remains fail-closed/watch-only rather than manufacturing confidence.
- Professional Transaction Preflight remains the metered pre-sign customer decision surface.
- Professional State Recheck remains the immediate entitlement-only continuation for the same signing decision and never signs or broadcasts.
- Paid access is controlled only by active server-side SaaS entitlements. Payment-provider observations are collection/audit evidence, not authorization authority.
- Paddle is being retired from the active browser, runtime, owner, OpenAPI, CI, and current product/documentation contract in PR #975.
- Existing applied Paddle-named migration history and historical database rows are preserved for migration/audit integrity; they are not evidence that Paddle remains an active provider.
- Current supported entitlement activation provider records are `shopier`, `shopier_manual`, and `owner_manual`.
- Koschei Sentinel is cancelled. Koschei Lang is separate and deferred. Neither is an active Web3 dependency or implementation target.
- `main` remains unprotected, so exact-head, exact merge-candidate, and target-freshness verification remain mandatory.

## CHANGED

### PR #975 — Paddle retirement (verification pending)

The active branch removes Paddle from the live product contract without rewriting deployed migration history:

- removes Paddle checkout HTML/JS/CSS and static aliases;
- removes Paddle API inventory/rate-limit entries and OpenAPI Paddle signature/auth semantics;
- removes Paddle from owner health, status, and command surfaces;
- removes Paddle-specific pricing CI assumptions;
- updates Pricing, Support, Terms, payment-path documentation, and the architecture boundary so Paddle is no longer presented as the current Merchant of Record or commercial authority;
- preserves generic `payment_provider` / `external_payment_id` fields because they are provider-neutral audit/evidence fields;
- preserves Shopier/manual entitlement activation paths;
- changes unknown or retired payment-provider identifiers to fail closed instead of silently normalizing to `owner_manual`;
- adds regression coverage for the supported-provider boundary.

Applied migration `101_paddle_saas_billing_v1.sql`, the migration-numbering baseline, and migration-history documentation are intentionally preserved. Applied migration filenames are historical identities and must not be deleted or rewritten merely to remove a retired runtime provider.

### PR #968 — canonical dominant-holder evidence

PR #968 fixed a live actor-verdict evidence-binding defect:

- `DominantHolderTokenCount` is derived from canonical persisted `dominant_holder_of` rows grouped by distinct token mint;
- ARD-C002 now binds to that same canonical relation;
- only VERIFIED/OBSERVED rows with non-empty canonical evidence keys and token mints can bind the rule;
- evidence must cover at least the claimed distinct-mint count;
- same-mint duplicates and partial coverage cannot upgrade a verdict;
- insufficient proof remains visible as watch context rather than disappearing;
- Operator freshness validation was hardened to compare the tested synthetic merge candidate's base parent with live target state.

Merge commit: `163471aea13b7cd4671fe62f152b585b2e6ab468`.

### Previous verified production anchors

- PR #962: Professional State Recheck for the same pre-sign decision; exact transaction/network/witness binding; fail-closed on expired/unavailable/incomplete current-state evidence.
- PR #963: removed dangling retired payment-runtime references without restoring request-time payment authorization.
- PR #966: forward-only repair of historical immutable actor transaction-evidence recurrence inflation; immutable transaction evidence remains one chain observation per evidence key while legitimate snapshot/event recurrence semantics remain intact.

## VERIFIED

### Current `main`

- PR #968 is merged at `163471aea13b7cd4671fe62f152b585b2e6ab468`.
- The merged change includes positive canonical distinct-mint holder binding, same-mint rejection, and partial-coverage fail-closed regression tests.
- No newer `main` head has been observed during PR #975 preparation; PR #975 was created against base `163471aea13b7cd4671fe62f152b585b2e6ab468`.

### PR #975

**Not verified yet.** Do not call PR #975 merge-ready until its final exact head has passed the permanent PR gates and the synthetic merge candidate is proven against the current target head.

Repository-level inspection before opening #975 confirmed its branch was ahead of `main` with `behind_by = 0`, and the diff remained bounded to Paddle retirement, provider validation, supporting tests, and current documentation.

## BROKEN / MISSING

- PR #975 still needs final CI verification before merge.
- The repository product narrative still over-emphasizes historical scanner/Solana positioning in some surfaces; issue #851 remains relevant after the payment cleanup.
- The next product slice must not grow generic scanner/score breadth.
- Execution Proof still needs one real Safe-aware EVM vertical slice that binds exact payload + pinned state + invariants to a deterministic operator decision.
- Security Evidence Bus work (#855) is not yet the universal provenance/digest/status contract for Radar findings.
- Solana expansion must remain bounded; the next Solana intelligence slice is only Geyser event envelope + gap/dedupe + Token-2022 security semantics wired into the evidence pipeline.
- State Recheck reduces the time-of-check/time-of-signing window but cannot prove state will remain unchanged after the final observation and before network execution.

## NEXT

1. Finish PR #975 on the **same branch**. Fix any CI/review issue in-place; do not open another cleanup branch.
2. Require final-head verification for Go tests, vet, build, migrations, OpenAPI, pricing/public-product acceptance, security gates, exact synthetic merge candidate, and target-base freshness.
3. Merge #975 only after the exact head is green, then verify the actual merged `main` head.
4. After Paddle retirement is merged, make the next product priority **Execution Proof → Transaction Defense → Evidence → operator decision**.
5. Inspect issues/lineage #849 / #857 / #859 and finish one Safe-aware isolated EVM execution vertical slice: exact calldata/payload, pinned state, owner/threshold/module change semantics, asset outflow invariants, and deterministic `RELEASE / CONTAIN / UNAVAILABLE` output.
6. Continue #855 Security Evidence Bus so every serious Radar finding carries provenance, digest, source state (`observed` / `verified` / `unavailable`), confidence/limitations, and a reasoning path. Missing evidence must never become SAFE.
7. Then address #851 product presentation so Execution Proof / Transaction Defense / Evidence / operator decision are primary and legacy wallet/token scanner utilities are secondary.
8. For Solana, do not attack all of #862. Complete only Geyser event envelope + gap/dedupe + Token-2022 security semantics and connect that slice to the existing evidence pipeline.

## WORK-IN-PROGRESS POLICY

1. Keep **one active product/maintenance PR** at a time.
2. A CI failure does not justify a new feature branch; classify and repair it on the active branch when in scope.
3. New ideas go to backlog and do not interrupt the active production slice.
4. Do not revive stale branches or old PRs without a current-main semantic comparison proving capability is still missing.
5. Validate the exact synthetic merge candidate against the current target head and verify the actual merged `main` head afterward.
6. Temporary repair workflows/scripts must be removed before final merge.
7. Never rewrite an already-applied migration for cosmetic cleanup; use forward migrations when state repair is required and preserve filename identity.
8. Chat history is context only; current GitHub state plus this checkpoint is authoritative.

## DO NOT START

- No generic scanner/risk-score expansion as the primary product direction.
- No fake scores, fake chain data, placeholder enterprise capabilities, or disconnected demo surfaces.
- No revival of retired Paddle or KOSCH/asset-based commercial authorization.
- No Koschei Sentinel implementation or integration target.
- No Koschei Lang implementation inside this repository; it remains a separate deferred project.
- No broad multi-chain abstraction work before one production-grade Execution Proof vertical slice proves the model.

## RISKS

- **Unprotected main:** target can move without branch-protection enforcement; exact candidate freshness is mandatory.
- **Migration-history risk:** Paddle-named historical migrations must not be deleted/renumbered merely because the provider is retired.
- **Provider-confusion risk:** payment collection evidence must never become entitlement authority; unknown providers fail closed.
- **Evidence-quality risk:** a finding without provenance/canonical evidence can become misleading if treated as a positive safety conclusion.
- **Product-positioning risk:** scanner-heavy UI/copy can obscure the actual differentiation: validating defenses before execution and proving the operator decision.
- **Execution-proof risk:** simulation without exact payload/state binding or invariant evidence can produce a false sense of safety.
- **Cross-chain scope risk:** expanding chains before the common evidence/decision contract is proven would couple chain-specific code to core intelligence.
