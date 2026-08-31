# Koschei Web3 Project State

This file is the authoritative repository checkpoint for continuing Koschei Web3 work across chat/session boundaries. Current repository state wins over conversational assumptions and stale branch history.

## CURRENT STATE

- Current `main` head before this branch: **`3edcbc46e2cf80516df100bb91f3e08a09980cb4`**, merged by PR **#978**, `docs: checkpoint Polar production billing state`.
- Koschei Web3 is currently a **Solana-first evidence-backed security and risk-intelligence product**. The production Transaction Guard explicitly supports `solana-mainnet` only.
- The production pre-sign decision vocabulary already used by Transaction Guard is **`allow / warn / block / withhold`**.
- Unified Radar still publishes a separate letter-grade contract (`A`-`F` or `-`).
- EVM Execution Containment is an isolated Enterprise validation subsystem with legacy decisions **`RELEASE / CONTAIN / UNAVAILABLE`**. It is not the Web3 product's canonical decision authority and must not become the product spine.
- `internal/executionproof` and related Safe/Anvil/Solidity work are retained but **frozen as a secondary isolated capability** until Solana decision/evidence gaps are closed.
- ARVIS remains the active core and should evolve along **Address -> Entity -> Transaction -> Behavior -> Attack Path -> Evidence** without replacing working Solana collectors.
- Four ARVIS evidence arms are defined but currently hard-coded unavailable in `AnalyzeArvisRadarsContext`: `liquidity_movement`, `creator_link_analysis`, `launch_distribution`, and `repeat_actor_scan`.
- Polar is the active SaaS checkout edge. Paddle runtime is retired. Paid access remains controlled only by server-side entitlements.
- Production hosted checkout has been observed successfully: `POST /api/polar/checkout` returned HTTP 200 and redirected to the real Polar hosted checkout. A real paid webhook/entitlement activation has not yet been executed.
- Koschei Sentinel is cancelled. Koschei Lang is separate and deferred; neither is an active Web3 implementation dependency.
- `main` remains unprotected, so exact-head, exact merge-candidate and target-freshness verification remain mandatory before merge.

## CHANGED

### Active branch — Solana-centered decision contract

This branch begins the decision-contract convergence without changing existing public legacy fields yet:

- adds `internal/decision` with the canonical action vocabulary `allow / warn / block / withhold`;
- maps Transaction Guard actions without semantic translation;
- maps Unified Radar grades into the canonical action vocabulary (`A/B -> allow`, `C -> warn`, `D/E/F -> block`, `- -> withhold`);
- maps isolated EVM containment results only through an adapter (`RELEASE -> allow`, `CONTAIN -> block`, `UNAVAILABLE -> withhold`);
- preserves source and legacy values so compatibility does not erase provenance;
- requires a `withhold_reason` whenever the canonical action is withheld.

This package is a convergence foundation. Existing APIs are not yet rewritten around it in this branch.

### Polar production billing

- PR #975 retired Paddle browser/runtime/API/CSP surfaces while preserving applied migration history.
- PR #976 repaired the stale Actor Reference production readiness marker.
- PR #977 added authenticated Polar hosted checkout, verified raw-body webhook handling, provider-event idempotency, subscription activation/revocation and paid-cycle quota renewal.
- PR #978 recorded the successful production configuration/deployment and checkout smoke.

## VERIFIED

### Repository verification against previously proposed architecture claims

The following identifiers are **not present in current main** and must not be treated as implemented capabilities:

- `execution_proof_digest`
- `analysis_context_hash`
- `gate_stage`
- `remediation`
- `PROCEED`
- `REVIEW`

Current real decision surfaces are:

1. Solana Transaction Guard: `allow / warn / block / withhold`.
2. Unified Radar: letter grades `A`-`F` or `-` plus verdict/evidence contract.
3. EVM Execution Containment: `RELEASE / CONTAIN / UNAVAILABLE`.

The Transaction Guard code explicitly defaults to and enforces `solana-mainnet`; unsupported networks fail closed.

### ARVIS disconnected arms

`AnalyzeArvisRadarsContext` currently constructs these four arms using `unavailableArm(...)` even though supporting evidence collectors/relations exist elsewhere in the repository:

- `liquidity_movement`
- `creator_link_analysis`
- `launch_distribution`
- `repeat_actor_scan`

They must be connected to canonical evidence rather than filled with synthetic scores or inferred certainty.

### Billing

- Polar checkout route is live and returned HTTP 200 in production.
- Browser -> Koschei backend -> Polar hosted checkout was observed end-to-end without granting entitlement from the redirect.
- Polar secrets remain environment-only.

## BROKEN / MISSING

- The product still has three decision vocabularies. Canonical product semantics must converge around the Solana pre-sign vocabulary `allow / warn / block / withhold`, while legacy surface fields remain available during migration.
- The four ARVIS arms above are still disconnected from the main mint analysis path.
- A Solana adversarial fixture suite is missing for claims Koschei itself should try to break. Priority cases: fake LP-lock claims, ATA/freeze surprises, Token-2022 transfer-hook injection, authority mutation, incorrect mint/account resolution and incomplete state evidence.
- The customer UI still exposes internal ARVIS/rule jargon in places; deterministic reason codes and evidence need a customer explanation layer without changing the underlying evidence truth.
- `internal/agents` contains CRM/business-agent concerns that should be isolated from the security-intelligence runtime after the active product slice is complete.
- `internal/executionproof` is heavily EVM/Safe/Anvil-oriented and has no Solana evidence role. Do not delete it, but do not use it as the product architecture spine.
- Intent binding is not a greenfield layer: Transaction Guard v3 already has signed UI intent, decoded instruction evidence, state witness and enforcement-permit foundations. The next Solana step is to complete exact approved-instruction-set vs candidate-instruction-set binding using these existing primitives.
- A real paid Polar transaction has not yet verified signed webhook -> provider event ledger -> entitlement -> premium access in production.

## NEXT

1. Finish and verify the canonical decision contract on this branch. Do not change existing API semantics until mappings are test-locked.
2. On the next production slice, expose the canonical action + `withhold_reason` alongside legacy fields on Transaction Guard and Unified Radar responses; map EVM containment only as a compatibility adapter.
3. Connect the four existing ARVIS mint-path arms to canonical evidence, one bounded evidence source at a time: liquidity movement, creator link, launch distribution, repeat actor scan. Missing evidence must stay `withhold/unavailable`, never SAFE.
4. Add adversarial Solana fixtures for fake LP lock, freeze/ATA surprises, Token-2022 transfer hooks, authority changes, wrong mint resolution and incomplete state witness.
5. Complete Transaction Guard intent binding around the exact approved Solana instruction set versus the candidate instruction set; reuse state witness and enforcement permit instead of inventing an EVM-style replacement layer.
6. Isolate CRM/business-agent code from `internal/agents` without touching security runtime behavior.
7. Keep EVM executionproof frozen as a secondary Enterprise capability until the Solana decision/evidence path is coherent and production-proven.
8. Verify one controlled real Polar payment/webhook/entitlement cycle when commercially practical.

## WORK-IN-PROGRESS POLICY

1. Keep one active product/maintenance PR at a time.
2. A CI failure does not justify a new feature branch; classify and repair it on the active branch when in scope.
3. New ideas go to backlog and do not interrupt the active production slice.
4. Do not revive stale branches or old PRs without a current-main semantic comparison proving capability is still missing.
5. Validate the exact synthetic merge candidate against the current target head and verify actual merged `main` afterward.
6. Temporary repair workflows/scripts must be removed before final merge.
7. Never rewrite an already-applied migration for cosmetic cleanup; use forward migrations and preserve filename identity.
8. Secrets remain environment-only and must never be committed, exposed to browser bundles or logged.
9. Chat history is context only; current GitHub state plus this checkpoint is authoritative.

## DO NOT START

- No generic scanner/risk-score expansion as the primary product direction.
- No fake scores, fake chain data, fake payment evidence, placeholder enterprise capabilities or disconnected demo surfaces.
- No invented architecture identifiers or undocumented fields presented as if they already exist.
- No EVM-first product rewrite and no promotion of Safe/Anvil executionproof to the Web3 product spine.
- No revival of Paddle or KOSCH/token-backed commercial authorization.
- No Koschei Sentinel implementation/integration target.
- No Koschei Lang implementation inside this repository.
- No broad multi-chain abstraction before the Solana evidence/decision contract is production-coherent.

## RISKS

- **Decision drift:** three vocabularies can produce contradictory operator language unless canonical mapping is explicit and source-preserving.
- **Evidence gap:** disconnected ARVIS arms can create the impression of architecture breadth while remaining unavailable in the actual mint path.
- **EVM gravity:** a large, well-tested EVM subsystem can pull roadmap attention away from the production Solana product despite having limited customer-path reach.
- **Evidence-quality risk:** missing or incomplete evidence must never silently improve a decision.
- **Intent-binding risk:** simulation without exact approved-vs-candidate instruction binding can create false confidence before signing.
- **Product-positioning risk:** internal rule IDs and collector jargon can obscure the operator question: what should I do, why, what can happen, and can I verify it?
- **Billing proof risk:** successful checkout creation is not the same as a completed paid entitlement cycle.
- **Unprotected main:** target can move without branch protection; exact candidate freshness remains mandatory.
