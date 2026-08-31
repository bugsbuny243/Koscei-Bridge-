# Koschei Web3 Project State

This file is the authoritative repository checkpoint for continuing Koschei Web3 work across chat/session boundaries. Current repository state wins over conversational assumptions and stale branch history.

## CURRENT STATE

- Current verified `main` head: **`511135f20e1e6d869893e735f5764721078e3ce3`**, merge of PR **#979**, `fix(decision): restore Solana-centered decision contract`.
- Koschei Web3 is a **Solana-first evidence-backed security and risk-intelligence product**. Production Transaction Guard supports `solana-mainnet` and uses the operator action vocabulary **`allow / warn / block / withhold`**.
- PR #979 added a source-preserving canonical decision adapter around that vocabulary. Unified Radar letter grades and isolated EVM containment values are compatibility inputs, not the product decision spine.
- `internal/executionproof` / Safe / Anvil remains retained but frozen as a secondary isolated Enterprise capability while Solana evidence gaps are closed.
- ARVIS remains the active product core and evolves along **Address -> Entity -> Transaction -> Behavior -> Attack Path -> Evidence**.
- Four ARVIS mint-path arms remain hard-coded unavailable in `AnalyzeArvisRadarsContext`: `liquidity_movement`, `creator_link_analysis`, `launch_distribution`, and `repeat_actor_scan`.
- Polar remains the billing provider integration and server-side entitlements remain the only paid-access authority.
- Active branch: **`fix/commercial-readiness-ui`**. It pauses new commercial checkout by default and removes customer-facing paid checkout while production readiness is incomplete. Existing entitlement/webhook lifecycle handling is intentionally preserved.
- Koschei Sentinel is cancelled. Koschei Lang is separate and deferred; neither is an active Web3 implementation dependency.
- `main` remains unprotected; exact-head, exact merge-candidate and target-freshness verification are mandatory before merge.

## CHANGED

### PR #979 — Solana-centered decision contract

Merged and CI-verified:

- canonical actions: `allow / warn / block / withhold`;
- Transaction Guard maps without semantic translation;
- Unified Radar and EVM containment map through source-preserving compatibility adapters;
- unknown values fail closed to `withhold` with a reason;
- EVM executionproof is explicitly not the Web3 architecture spine;
- checkpoint records the four disconnected ARVIS arms as the next core product gap.

### Active branch — commercial readiness / UI integrity

This branch addresses the customer-facing contradictions observed on the live site:

- new Polar checkout creation is fail-closed unless `KOSCHEI_COMMERCIAL_CHECKOUT_ENABLED` is explicitly enabled server-side;
- Polar webhook handling, renewal/revoke processing and existing entitlements are not disabled;
- `/pricing` no longer exposes Starter / Professional / Enterprise prices or `Subscribe with Polar` buttons while checkout is paused;
- `/pricing` now presents Free Core plus one **Request early access** form backed by the existing feedback persistence path and explicitly states that no payment is taken;
- `/reports` no longer concatenates backend machine error identifiers such as `plan_tier_required` into customer-facing copy;
- scan navigation no longer collapses mode-specific customer sidebar routes into a single `Scan Center` entry;
- the dashboard self-promo safety strip is suppressed so it cannot overlap the workspace navigation;
- regression tests lock the server checkout gate, pricing pause contract, reports error boundary, sidebar preservation and promo suppression.

## VERIFIED

### PR #979

Exact PR head **`e95676c227094cb671e1fd2f8a35570129c5586e`** passed all observed permanent gates before merge:

- API Required CI;
- Public Product Smoke;
- Auth Freeze Guard;
- Security CI;
- CodeQL;
- Supply Chain Security;
- Operator Exit Corpus Acceptance;
- Release Gates Verification, including PostgreSQL migration chain, Go tests/vet/build/race checks, merge-candidate verification and target freshness.

PR #979 merged as **`511135f20e1e6d869893e735f5764721078e3ce3`**.

### Repository truth retained

- Transaction Guard is Solana-only at the current production boundary.
- EVM Execution Containment uses `RELEASE / CONTAIN / UNAVAILABLE` and remains isolated.
- Previously claimed identifiers `execution_proof_digest`, `analysis_context_hash`, `gate_stage`, `remediation`, `PROCEED` and `REVIEW` are not current repo capabilities and must not be represented as implemented.
- The four disconnected ARVIS arms above are real integration gaps, not missing labels.

### Active branch verification

Pending CI. Do not merge or call the commercial-readiness changes production-verified until the exact branch head is green.

## BROKEN / MISSING

- `liquidity_movement`, `creator_link_analysis`, `launch_distribution` and `repeat_actor_scan` are still disconnected from the main ARVIS mint path.
- A Solana adversarial fixture set is still missing for fake LP-lock claims, ATA/freeze surprises, Token-2022 transfer-hook injection, authority mutation, wrong mint/account resolution and incomplete state evidence.
- Exact approved-instruction-set vs candidate-instruction-set binding is not complete; Transaction Guard v3 already has signed UI intent, decoding, state witness and enforcement-permit primitives that should be extended rather than replaced.
- Anonymous `/dashboard` still renders the empty operational shell before/around the sign-in state; this should later become a cleaner authentication boundary without invented sample data.
- `/feedback` still contains legacy Turkish source copy even though primary customer surfaces are English; clean this separately after the current bounded PR.
- Enterprise pricing economics are intentionally not being tuned while new checkout is paused. Revisit package value/capacity only after production readiness is proven.
- The public domain `tradepigloball.co` remains a product-trust liability for a dedicated security brand. Domain migration is an external product/brand task and must not be faked in repo code before a real domain is selected and controlled.
- A real paid Polar payment -> signed webhook -> provider event ledger -> entitlement activation cycle has not yet been proven in production.
- `internal/agents` contains CRM/business-agent concerns that should eventually be isolated from the security-intelligence runtime.

## NEXT

1. Finish CI for the active commercial-readiness/UI branch and merge only on an exact green head.
2. Verify production no longer offers a new paid checkout and that existing webhook/entitlement behavior remains intact.
3. Return immediately to the ARVIS core: connect `liquidity_movement` to canonical existing LP/liquidity evidence first.
4. Then connect `creator_link_analysis`, `launch_distribution`, and `repeat_actor_scan` one bounded evidence source at a time. Missing evidence must remain unavailable/withheld, never SAFE.
5. Add adversarial Solana fixtures that try to break Koschei's own claims.
6. Complete exact Solana instruction-intent binding using Transaction Guard v3 + state witness + enforcement permit.
7. Only after the customer pipeline is operationally healthy should paid pricing/checkout be deliberately re-enabled and package economics revisited.

## WORK-IN-PROGRESS POLICY

1. Keep one active product/maintenance PR at a time.
2. Classify and repair CI failures on the active branch when in scope; do not branch-hop to avoid them.
3. Do not revive stale branches or old PRs without a current-main semantic comparison proving capability is still missing.
4. Validate the exact synthetic merge candidate against the current target head and verify actual merged `main` afterward.
5. Temporary repair workflows/scripts must be removed before final merge.
6. Never rewrite already-applied migration history for cosmetic cleanup.
7. Secrets remain environment-only and must never be committed, exposed to browser bundles or logged.
8. Chat history is context only; current GitHub state plus this checkpoint is authoritative.

## DO NOT START

- No generic scanner/risk-score expansion as the primary product direction.
- No fake scores, fake chain data, fake payment evidence, placeholder enterprise capabilities or disconnected demo surfaces.
- No EVM-first product rewrite and no promotion of Safe/Anvil executionproof to the product spine.
- No new paid checkout while commercial readiness remains explicitly paused.
- No revival of Paddle or KOSCH/token-backed commercial authorization.
- No Koschei Sentinel implementation/integration target.
- No Koschei Lang implementation inside this repository.
- No broad multi-chain abstraction before the Solana evidence/decision contract is production-coherent.

## RISKS

- **Commercial trust risk:** accepting payment while the product itself reports degraded/incomplete evidence damages the first-customer reference more than a temporary checkout pause.
- **Evidence gap risk:** disconnected ARVIS arms can overstate architecture breadth if presented as available functionality.
- **Decision drift risk:** legacy letter grades and EVM containment values can contradict operator language if not mapped through the canonical Solana action contract.
- **Evidence-quality risk:** missing or incomplete evidence must never silently improve a decision.
- **Intent-binding risk:** simulation without exact approved-vs-candidate instruction binding can create false confidence before signing.
- **Provider lifecycle risk:** pausing new checkout must never accidentally stop legitimate renewal/revoke webhook processing for existing entitlements.
- **Brand trust risk:** the current domain and legacy product naming are weaker trust signals than the security engine itself.
- **Unprotected main:** target can move without branch protection; exact candidate freshness remains mandatory.
