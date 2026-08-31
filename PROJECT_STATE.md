# Koschei Web3 Project State

This file is the authoritative repository checkpoint for continuing Koschei Web3 work across chat/session boundaries. Current repository state wins over conversational assumptions and stale branch history.

## CURRENT STATE

- Current verified `main` head: **`4a8a6f39357bd31cb0c60b313ae025a0af356464`**, merge of PR **#980**, `fix(commercial): pause checkout until evidence readiness`.
- Railway successfully deployed that exact main commit and the public API transport health status was successful.
- Koschei Web3 is a **Solana-first evidence-backed security and risk-intelligence product**. Transaction Guard uses the canonical operator action vocabulary **`allow / warn / block / withhold`**.
- PR #979 added the source-preserving canonical decision adapter. Unified Radar letter grades and isolated EVM containment remain compatibility inputs, not the product decision spine.
- New paid checkout is paused by default. Polar webhook/renewal/revoke and existing entitlement processing remain intact; server-side entitlements are the only paid-access authority.
- ARVIS remains the active product core and evolves along **Address -> Entity -> Transaction -> Behavior -> Attack Path -> Evidence**.
- Important repo-truth correction: `liquidity_movement` is **not globally unimplemented**. Full investigation paths already collect market context and protocol-specific LP control evidence through `runHolderIntelligenceCore -> collectCompleteLPControlEvidence -> ApplyLPControlEvidenceToAnalysis`. The concrete gap found in this slice is that the Professional Exposure Report bypassed that chain and called the raw ARVIS compatibility path directly.
- Raw `AnalyzeArvisRadarsContext` intentionally still starts `liquidity_movement`, `creator_link_analysis`, `launch_distribution` and `repeat_actor_scan` as unavailable until a caller attaches canonical evidence. Do not confuse that service-layer default with the absence of collectors.
- Active PR: **#981**, branch **`feat/arvis-liquidity-evidence`**, binding the Professional Exposure Report to the canonical investigation/LP evidence chain.
- Koschei Sentinel is cancelled. Koschei Lang is separate and deferred; neither is an active Web3 implementation dependency.
- `main` remains unprotected; exact-head, exact merge-candidate and target-freshness verification are mandatory before merge.

## CHANGED

### PR #980 — commercial integrity / UI consistency

Merged and production-deployed:

- new Polar checkout is fail-closed unless `KOSCHEI_COMMERCIAL_CHECKOUT_ENABLED` is explicitly enabled server-side;
- public paid prices and `Subscribe with Polar` buttons are removed while readiness is incomplete;
- Free Core plus a real persisted early-access request path replaces active checkout;
- `/reports` no longer leaks machine identifiers such as `plan_tier_required` into customer copy;
- scan mode navigation no longer collapses Deep Investigation and Transaction Preflight into one link;
- the dashboard self-promo strip that overlapped navigation is suppressed;
- existing Polar webhook/renewal/revoke/entitlement lifecycle remains active.

### Active PR #981 — Professional Exposure liquidity evidence

This branch does not add a detector or a new score. It repairs an evidence-routing gap:

- `/api/v1/radar/exposure` now reuses `buildUnifiedInvestigationReport` instead of `AnalyzeArvisRadars` + `ArvisFinalFromBundle`;
- Exposure runs in bounded `exposure_report_stored_only` mode: market/holder/LP evidence runs, while the broader live actor/funding investigation is not started by this read surface;
- existing LP collection remains the source of truth: pool program, pool type, vaults, reserve balances, read slot, LP control/lock state and transaction-backed liquidity movement evidence;
- the Exposure liquidity section now projects the real canonical LP signal names instead of the stale placeholder keys `pool`, `reserve`, `liquidity`;
- the deterministic Unified Radar verdict is exposed together with the canonical `allow / warn / block / withhold` adapter;
- an unsigned/no-grade investigation with real evidence is no longer treated as a server failure or an approval; it remains a reportable evidence state and maps to `withhold`;
- shareable Exposure output no longer presents a numeric `/100` final score;
- regression tests lock LP signal projection, WITHHOLD semantics and canonical-investigation wiring.

## VERIFIED

### PR #980

Exact PR head passed all observed permanent workflows before merge, including API Required CI, Pricing SaaS Acceptance, Customer Workspace/Operations acceptance, Public Product Smoke, OpenAPI, Auth Freeze Guard, Security CI, CodeQL, Supply Chain, Canonical Investigation History, Operator Exit and Release Gates. Release verification included PostgreSQL 17 migrations, Go tests/race/vet/build, exact merge candidate and target freshness.

PR #980 merged as **`4a8a6f39357bd31cb0c60b313ae025a0af356464`** and Railway deployed that exact commit successfully.

### Liquidity evidence repo truth

Verified by current code inspection:

- `collectCompleteLPControlEvidence` already dispatches protocol-specific LP collectors and attaches transaction-backed liquidity movement evidence where available;
- `ApplyLPControlEvidenceToAnalysis` replaces both Pool Control Guardian and `liquidity_movement` without recalculating or signing a grade;
- completed LP evidence carries pool address/program/type, vaults, read slot, reserves, LP supply/control/lock evidence, dominant LP ownership context, movement status, movement signatures/slots/actors/kinds and canonical evidence keys;
- missing/unsupported/source-unavailable LP state stays not-applicable, source-unavailable or insufficient instead of becoming a low-risk finding;
- full investigation paths already call this chain; the Professional Exposure route was the concrete bypass fixed by PR #981.

### Active PR #981

CI is running. Do not merge or call the Exposure repair production-verified until the exact PR head is green.

## BROKEN / MISSING

- PR #981 still requires exact-head CI, merge-candidate and target-freshness verification.
- Raw ARVIS core still begins several handler-enriched arms as unavailable by design; remaining work is to audit which customer/operator entry points still bypass the existing evidence attachment stages.
- `creator_link_analysis`, `launch_distribution` and `repeat_actor_scan` require the same repo-truth audit before any new collector is written; existing handler/store capabilities must be reused where they already exist.
- A Solana adversarial fixture set is still missing for fake LP-lock claims, ATA/freeze surprises, Token-2022 transfer-hook injection, authority mutation, wrong mint/account resolution and incomplete state evidence.
- Exact approved-instruction-set vs candidate-instruction-set binding is not complete; Transaction Guard v3 already has signed UI intent, decoding, state witness and enforcement-permit primitives that should be extended rather than replaced.
- Production logs still report broad security-radar RPC workers paused under `SOLANA_RPC_LIMIT_SAVER_ENABLED=true`; manual scans/selective workers remain available. Operational health semantics must reflect that honestly.
- Anonymous `/dashboard` still needs a cleaner login-first boundary without fake sample data.
- `/feedback` still contains legacy Turkish source copy even though primary customer surfaces are English.
- `tradepigloball.co` remains a brand-trust liability; no domain migration should be faked before a real Koschei domain is selected and controlled.
- A real paid Polar payment -> signed webhook -> provider event ledger -> entitlement activation cycle has not yet been proven in production.

## NEXT

1. Finish #981 CI on the exact head; repair failures on the same branch.
2. Merge only after exact merge-candidate and target-freshness gates pass, then verify merged `main` and Railway production deployment.
3. Verify the live Professional Exposure route returns canonical liquidity evidence when available and explicit unavailable/insufficient state when not.
4. Audit `creator_link_analysis` entry points next: identify existing collectors/store relations first, then repair only the real bypass.
5. Repeat the same process for `launch_distribution` and `repeat_actor_scan`.
6. Add adversarial Solana fixtures that try to break Koschei's own evidence claims, beginning with fake LP-lock and liquidity-control cases.
7. Complete exact Solana instruction-intent binding using Transaction Guard v3 + state witness + enforcement permit.

## WORK-IN-PROGRESS POLICY

1. Keep one active product/maintenance PR at a time.
2. Classify and repair CI failures on the active branch; do not branch-hop to avoid them.
3. Inspect current repo truth before adding collectors, files or architecture layers.
4. Validate the exact synthetic merge candidate against the current target head and verify actual merged `main` afterward.
5. Temporary repair workflows/scripts must be removed before final merge.
6. Never rewrite already-applied migration history for cosmetic cleanup.
7. Secrets remain environment-only and must never be committed, exposed to browser bundles or logged.
8. Chat history is context only; current GitHub state plus this checkpoint is authoritative.

## DO NOT START

- No generic scanner/risk-score expansion as the primary product direction.
- No fake scores, fake chain data, fake payment evidence, placeholder enterprise capabilities or disconnected demo surfaces.
- No duplicate LP/liquidity collector when canonical evidence already exists.
- No EVM-first rewrite and no promotion of Safe/Anvil executionproof to the product spine.
- No new paid checkout while commercial readiness remains paused.
- No revival of Paddle or KOSCH/token-backed commercial authorization.
- No Koschei Sentinel implementation/integration target.
- No Koschei Lang implementation inside this repository.
- No broad multi-chain abstraction before the Solana evidence/decision contract is production-coherent.

## RISKS

- **Evidence-routing risk:** working collectors can appear "missing" when a customer route bypasses their attachment stage; fix the route before inventing duplicate intelligence.
- **Liquidity-proof risk:** market depth alone does not prove LP control or add/remove behavior; transaction-backed movement and on-chain pool/vault evidence must remain distinct.
- **Decision drift risk:** legacy compatibility finals can turn evidence gaps into contradictory customer behavior unless surfaces use the deterministic Unified Radar verdict and canonical action adapter.
- **RPC-budget risk:** advanced read surfaces must reuse bounded/stored evidence modes where live actor expansion is unnecessary.
- **Evidence-quality risk:** missing or incomplete evidence must never silently improve a decision.
- **Commercial trust risk:** paid checkout remains paused until the customer evidence pipeline is operationally credible.
- **Unprotected main:** target can move without branch protection; exact candidate freshness remains mandatory.
