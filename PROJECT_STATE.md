# Koschei Web3 Project State

This file is the authoritative repository checkpoint for continuing Koschei Web3 work across chat/session boundaries. Current repository state wins over conversational assumptions and stale branch history.

## CURRENT STATE

- Current verified `main` head: **`3118cd4835a43b23c26e00e44afd580e5254071a`**, merged by PR **#977**, `feat: add Polar SaaS billing edge`.
- PR #975 retired the active Paddle browser/runtime/API/CSP surface while preserving applied migration history and provider-neutral audit fields.
- PR #976 aligned Actor Reference production acceptance with the deployed `ARVIS Public Live Radar` marker.
- PR #977 added production Polar hosted checkout and verified webhook-driven SaaS entitlement handling.
- Railway production service `koschei-web3-hub` deploys from `main`; deployment after Polar credential configuration completed successfully on 2026-08-31.
- Polar production configuration is present in Railway for access token, webhook secret, environment, trusted redirect URLs, and Starter / Professional / Enterprise Product IDs. Secret values are environment-only and are not stored in the repository.
- Paid access remains controlled only by active server-side SaaS entitlements. A successful checkout redirect is never authorization.
- Professional Transaction Preflight remains the metered pre-sign customer decision surface.
- Professional State Recheck remains the entitlement-only continuation for the exact same transaction/network/state witness and never signs or broadcasts.
- Koschei Sentinel is cancelled. Koschei Lang is separate and deferred; neither is an active Web3 implementation dependency.
- `main` remains unprotected, so exact-head, exact merge-candidate and target-freshness verification remain mandatory before merge.

## CHANGED

### PR #977 — Polar SaaS billing edge

Polar is now the active SaaS checkout edge for Web3 packages:

- authenticated server-side `POST /api/polar/checkout` creates hosted checkout sessions;
- browser sends only the canonical plan ID; price, Polar Product ID and credentials remain server-side;
- Polar access token is environment-only and scoped to checkout creation;
- `POST /api/polar/webhook` verifies the raw webhook body before event data is trusted;
- webhook replay window and event identity are validated;
- duplicate provider events are idempotent through the provider-neutral billing event ledger;
- raw payment payloads are not stored; a digest plus normalized event evidence is persisted;
- `subscription.active` may activate the exact Polar subscription entitlement only after product/plan/customer binding checks pass;
- `subscription.revoked` revokes only the exact Polar provider/subscription entitlement and preserves independent manual/provider grants;
- a newer/equal recorded revocation suppresses stale activation events;
- `subscription.canceled` and `subscription.past_due` do not immediately revoke access by themselves;
- quota renewal occurs only from a verified paid `order.paid` event with `billing_reason=subscription_cycle` and an active correctly-bound subscription;
- pending orders, unpaid orders, ordinary purchases and proration/update orders do not refresh quota;
- pricing CTAs for Starter / Professional / Enterprise call the authenticated Koschei checkout route instead of embedding provider product IDs or secrets in the browser;
- migration `119_polar_billing_v1.sql` adds provider-neutral billing event evidence/idempotency support.

### PR #975 — Paddle retirement

- removed Paddle checkout HTML/JS/CSS and static aliases;
- removed Paddle API routes, handlers, config code and Paddle-specific CSP exceptions;
- removed Paddle from current owner/OpenAPI/pricing/runtime contracts;
- added regression coverage so retired Paddle endpoints/CSP exceptions cannot silently return;
- preserved applied Paddle-named migration history and historical database rows for migration/audit integrity;
- unknown/retired provider identifiers fail closed instead of normalizing to trusted manual activation.

### PR #976 — production Actor Reference readiness

- fixed stale production acceptance assertions that still expected `ARVIS Public SOC`;
- acceptance now checks the deployed `ARVIS Public Live Radar` marker;
- no actor-intelligence runtime semantics changed.

### Evidence and preflight anchors retained

- PR #968: dominant-holder reuse is bound to canonical `dominant_holder_of` evidence and distinct token-mint coverage.
- PR #966: immutable transaction evidence normalization prevents replay/rescan inflation from manufacturing recurrence.
- PR #962: Professional State Recheck binds the same serialized transaction, network and state witness and fails closed on expired/unavailable/incomplete evidence.
- PR #960: Professional customer Transaction Preflight renders evidence semantics instead of numeric risk authority and never signs or broadcasts.

## VERIFIED

### PR #977 exact final head

Final Polar head **`8f5cbd51eb6df53c5a2faf5ccef5e028dfd07987`** passed all observed permanent PR gates before merge, including:

- API Required CI;
- PostgreSQL migration chain on PostgreSQL 17;
- full Go tests;
- `go vet` and build;
- release race tests;
- exact merge-candidate verification and target-base freshness;
- OpenAPI Contract;
- Pricing SaaS Acceptance;
- Public Product Smoke;
- Auth Freeze Guard;
- Security CI / Gitleaks / reachable vulnerability / static security scans;
- CodeQL;
- Supply Chain Security;
- Canonical Investigation History;
- Funding Cluster / Trajectory / Outcome memory acceptance;
- Persistent Actor Memory;
- Operator Exit Corpus Acceptance.

PR #977 was merged with merge commit **`3118cd4835a43b23c26e00e44afd580e5254071a`**.

### Production

After the real Polar production variables were configured in Railway:

- production redeployed successfully from main commit `3118cd4835a43b23c26e00e44afd580e5254071a`;
- database connection succeeded;
- migration startup reported all 117 migrations already applied/skipped (`0/117` newly required on the credential-only redeploy), confirming schema state remained current;
- API started listening on `:8080`;
- canonical plans synced and normal Web3 workers started;
- no repository or frontend secret was introduced.

The Polar account currently has production products for Starter, Professional and Enterprise and a production webhook endpoint at `https://tradepigloball.co/api/polar/webhook` configured in Raw format for:

- `order.paid`;
- `subscription.active`;
- `subscription.revoked`.

## BROKEN / MISSING

- No known code/CI/deploy blocker remains for the Polar billing edge.
- A real end-to-end purchase has **not yet been executed**. Before calling billing commercially proven, perform one controlled real/sandbox-equivalent checkout path and verify: checkout creation -> Polar payment -> signed webhook -> provider event ledger -> entitlement activation -> customer premium access. Do not fake this verification.
- Renewal and revoke behavior are covered by code/tests but should later be observed against real Polar events in production before relying on them as operational evidence.
- Railway still contains historical `PI_LANG_*` variable names from an older scope mistake. They are not an active Web3 dependency and should be removed from the Web3 service only after confirming no current Web3 code path references them. Do not modify the separate Lang service.
- Historical `KOSCHEI_TOKEN_*` configuration still exists for public/auditable token-launch metadata/readiness. Token-backed commercial authorization remains retired and ignored; do not revive it as a paid-access mechanism.
- Product presentation still over-emphasizes legacy scanner/Solana positioning in some surfaces; issue #851 remains relevant.
- Execution Proof still needs one production-grade Safe-aware EVM vertical slice binding exact payload + pinned state + invariants to a deterministic operator decision.
- Security Evidence Bus #855 is not yet the universal provenance/digest/source-state/confidence/reasoning-path contract for all serious findings.
- Solana expansion should remain bounded to evidence-quality work such as Geyser event envelope + gap/dedupe + Token-2022 semantics rather than broad scanner growth.

## NEXT

1. Perform one controlled production checkout smoke path without granting authority from the browser or success redirect. Verify server-created Polar checkout and signed webhook delivery.
2. Confirm the resulting `billing_provider_events` evidence and exact Polar entitlement activation in the database/customer access surface.
3. Observe one renewal and revoke event when practical; keep paid renewal dependent on verified `order.paid` subscription-cycle evidence.
4. Remove obsolete `PI_LANG_*` variables from the Web3 Railway service only after repo/runtime reference verification; never touch the separate Lang service from this workspace.
5. Return product focus to **Execution Proof -> Transaction Defense -> Evidence -> operator decision**.
6. Inspect issues/lineage #849 / #857 / #859 and finish one Safe-aware isolated EVM execution slice: exact calldata/payload, pinned state, owner/threshold/module semantics, asset-outflow invariants and deterministic `RELEASE / CONTAIN / UNAVAILABLE` output.
7. Continue #855 Security Evidence Bus: provenance, digest, source state (`observed` / `verified` / `unavailable`), confidence/limitations and reasoning path. Missing evidence must never become SAFE.
8. Address #851 product presentation after the execution slice so legacy wallet/token scanner utilities remain secondary.

## WORK-IN-PROGRESS POLICY

1. Keep one active product/maintenance PR at a time.
2. A CI failure does not justify a new feature branch; classify and repair it on the active branch when in scope.
3. New ideas go to backlog and do not interrupt the active production slice.
4. Do not revive stale branches or old PRs without a current-main semantic comparison proving capability is still missing.
5. Validate the exact synthetic merge candidate against the current target head and verify the actual merged main head afterward.
6. Temporary repair workflows/scripts must be removed before final merge.
7. Never rewrite an already-applied migration for cosmetic cleanup; use forward migrations and preserve filename identity.
8. Secrets remain environment-only and must never be committed, exposed to browser bundles or logged.
9. Chat history is context only; current GitHub state plus this checkpoint is authoritative.

## DO NOT START

- No generic scanner/risk-score expansion as the primary product direction.
- No fake scores, fake chain data, fake payment evidence, placeholder enterprise capabilities or disconnected demo surfaces.
- No revival of Paddle or KOSCH/token-backed commercial authorization.
- No Koschei Sentinel implementation/integration target.
- No Koschei Lang implementation inside this repository.
- No broad multi-chain abstraction before one production-grade Execution Proof vertical slice proves the common evidence/decision model.

## RISKS

- **Unprotected main:** target can move without branch protection; exact candidate freshness remains mandatory.
- **Billing proof risk:** successful deployment/configuration is not the same as a real completed purchase; commercial readiness requires controlled end-to-end evidence.
- **Provider-confusion risk:** Polar events are provider evidence, not authorization authority. Only server-side entitlement logic may grant access.
- **Secret hygiene risk:** Polar access token and webhook secret must remain Railway/environment-only.
- **Migration-history risk:** retired-provider migration history must not be deleted or renumbered.
- **Evidence-quality risk:** a finding without provenance/canonical evidence can become misleading if treated as positive safety evidence.
- **Product-positioning risk:** scanner-heavy UI/copy can obscure the differentiation: validating defenses before execution and proving the operator decision.
- **Execution-proof risk:** simulation without exact payload/state binding or invariant evidence can create a false sense of safety.
- **Cross-chain scope risk:** expanding chains before the common evidence/decision contract is proven would couple chain-specific code to core intelligence.
