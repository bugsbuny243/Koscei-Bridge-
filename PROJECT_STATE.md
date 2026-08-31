# Koschei Web3 Project State

This file is the authoritative repository checkpoint for continuing Koschei Web3 work across chat/session boundaries. Current repository state wins over conversational assumptions and stale branch history.

## CURRENT STATE

- Current verified `main` head: **`a84c5406c40f409b9f1717c4581a7fdbc19d9d4d`**, merge of PR **#981**, `fix(arvis): bind exposure to canonical liquidity evidence`.
- Railway deployed that exact main commit successfully. Public API transport `/health` and public product `/scan` statuses are successful.
- Koschei Web3 is a **Solana-first evidence-backed security and risk-intelligence product**. Transaction Guard uses the canonical operator action vocabulary **`allow / warn / block / withhold`**.
- New paid checkout remains paused by default. Polar webhook/renewal/revoke and existing entitlement processing remain intact; server-side entitlements are the only paid-access authority.
- ARVIS remains the active product core and evolves along **Address -> Entity -> Transaction -> Behavior -> Attack Path -> Evidence**.
- Repo-truth correction retained: raw `AnalyzeArvisRadarsContext` intentionally starts handler-enriched arms such as `liquidity_movement`, `creator_link_analysis`, `launch_distribution` and `repeat_actor_scan` unavailable until callers attach canonical evidence. This service-layer default is not proof that collectors are absent.
- PR #981 proved this distinction for liquidity: the LP/control collectors already existed; the Professional Exposure route was bypassing them. That route now consumes the canonical unified investigation/LP evidence chain.
- `creator_link_analysis` is also already attached by the full investigation path through `ApplyCreatorAndLiquidityEvidenceToAnalysis`. The current defect is provenance inflation: a non-empty creator attribution was being emitted as `real_onchain_evidence=true` even when canonical create-transaction verification was not attached.
- Active branch: **`fix/arvis-creator-provenance`**. It makes creator evidence VERIFIED on-chain only when a canonical create anchor is present with a positive slot; source-only attribution remains OBSERVED.
- Koschei Sentinel is cancelled. Koschei Lang is separate and deferred; neither is an active Web3 implementation dependency.
- `main` remains unprotected; exact-head, exact merge-candidate and target-freshness verification are mandatory before merge.

## CHANGED

### PR #981 — Professional Exposure canonical liquidity evidence

Merged and production-deployed:

- `/api/v1/radar/exposure` reuses the canonical unified investigation path instead of the raw ARVIS compatibility path;
- Exposure runs in bounded `exposure_report_stored_only` mode so LP/market evidence is collected without starting broader live actor/funding expansion;
- the liquidity section projects real pool/program/vault/reserve/read-slot/LP-control/liquidity-movement evidence;
- stale placeholder signal keys were removed;
- deterministic Unified Radar verdict plus canonical `allow / warn / block / withhold` decision semantics are used;
- evidence can be returned without a signed letter grade and remains `withhold` rather than becoming an approval or server failure;
- shareable Exposure output no longer presents a numeric `/100` final score.

### Active branch — creator-link provenance integrity

This branch does not add a new creator detector. It tightens the existing creator arm:

- creator attribution no longer becomes `real_onchain_evidence` merely because a creator wallet string exists;
- `verified_canonical_create_*` launch anchor plus a positive Solana slot is required for `creator_relation_verified=true`, `verified_evidence=true` and `real_onchain_evidence=true`;
- source-only creator attribution remains a signed OBSERVED evidence arm and is represented as source/off-chain evidence;
- a canonical label without a positive slot fails closed and cannot upgrade the relation;
- creator-link evidence continues to make no real-world identity or wrongdoing claim and cannot issue a score or grade;
- regression tests cover OBSERVED source attribution, VERIFIED canonical creator relation, and missing-slot fail-closed behavior.

## VERIFIED

### PR #981

Exact PR head **`006479438ff374d2e30b9759947a3376a837d3fc`** passed all observed permanent workflows before merge:

- API Required CI;
- Public Product Smoke;
- Auth Freeze Guard;
- Security CI;
- CodeQL;
- Supply Chain Security;
- Operator Exit Corpus Acceptance;
- Release Gates Verification.

Release verification included gofmt, PostgreSQL 17 migration/retention checks, full Go tests, race tests, vet, build, exact merge-candidate verification and target freshness.

PR #981 merged as **`a84c5406c40f409b9f1717c4581a7fdbc19d9d4d`**. Railway deployment, public API transport and public product status all reported success for that merged commit.

### Creator-link repo truth

Verified by current code inspection:

- `runHolderIntelligenceCore` already resolves creator source context and invokes Launch Forensics before applying the creator-link arm;
- `verifyCanonicalCreatorRelation` is the authoritative upgrade path and requires the creator to sign the candidate create transaction, the requested mint to be structurally referenced, launch/create semantics to be present, and a positive slot;
- external discovery providers may suggest creator/signature data but cannot themselves set the canonical relation VERIFIED;
- Launch Forensics preserves canonical create anchors as `verified_canonical_create_transaction` or `verified_canonical_create_slot` when the anchor is valid;
- the previous creator arm ignored that distinction and marked any creator string as real on-chain evidence; the active branch repairs this mismatch.

### Active branch verification

Pending CI. Do not merge or call the creator provenance repair production-verified until the exact branch head passes permanent gates.

## BROKEN / MISSING

- The active creator-provenance branch still requires exact-head CI, merge-candidate and target-freshness verification.
- Creator-link evidence still does not expose the canonical create transaction signature directly from the arm because the current `LaunchForensicsAnalysis` projection carries the canonical slot/source anchor but not that signature. Do not invent a signature. A later evidence-bus/provenance slice may carry the exact transaction reference end-to-end.
- `launch_distribution` and `repeat_actor_scan` require the same repo-truth audit before any new collector is written; existing handler/store capabilities must be reused where they already exist.
- A Solana adversarial fixture set is still missing for fake LP-lock claims, false creator attribution, ATA/freeze surprises, Token-2022 transfer-hook injection, authority mutation, wrong mint/account resolution and incomplete state evidence.
- Exact approved-instruction-set vs candidate-instruction-set binding is not complete; Transaction Guard v3 already has signed UI intent, decoding, state witness and enforcement-permit primitives that should be extended rather than replaced.
- Broad background security-radar RPC workers remain intentionally constrained by the RPC saver in production; manual scans/selective workers remain available.
- Anonymous `/dashboard` still needs a cleaner login-first boundary without fake sample data.
- `/feedback` still contains legacy Turkish source copy even though primary customer surfaces are English.
- `tradepigloball.co` remains a brand-trust liability; no domain migration should be faked before a real Koschei domain is selected and controlled.
- A real paid Polar payment -> signed webhook -> provider event ledger -> entitlement activation cycle has not yet been proven in production.

## NEXT

1. Run the exact creator-provenance branch through permanent CI; repair failures on the same branch.
2. Merge only after exact merge-candidate and target-freshness gates pass, then verify merged `main` and Railway deployment.
3. Audit `launch_distribution` next: determine whether its collectors/evidence already exist in Launch Forensics and identify the real entry-point or projection gap before writing code.
4. Audit `repeat_actor_scan` after launch distribution, reusing persistent creator/holder actor-index evidence where it already exists.
5. Add adversarial Solana fixtures that try to break Koschei's own evidence claims, including false creator attribution and fake LP-lock cases.
6. Complete exact Solana instruction-intent binding using Transaction Guard v3 + state witness + enforcement permit.

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
- No duplicate LP/liquidity or creator collector when canonical evidence already exists.
- No EVM-first rewrite and no promotion of Safe/Anvil executionproof to the product spine.
- No new paid checkout while commercial readiness remains paused.
- No revival of Paddle or KOSCH/token-backed commercial authorization.
- No Koschei Sentinel implementation/integration target.
- No Koschei Lang implementation inside this repository.
- No broad multi-chain abstraction before the Solana evidence/decision contract is production-coherent.

## RISKS

- **Creator-provenance risk:** source attribution must never be presented as canonical on-chain verification merely because a creator wallet string exists.
- **Evidence-routing risk:** working collectors can appear missing when a customer route bypasses their attachment stage; fix the route before inventing duplicate intelligence.
- **Liquidity-proof risk:** market depth alone does not prove LP control or add/remove behavior; transaction-backed movement and on-chain pool/vault evidence must remain distinct.
- **Decision drift risk:** legacy compatibility finals can turn evidence gaps into contradictory customer behavior unless surfaces use deterministic Unified Radar verdict and canonical action semantics.
- **RPC-budget risk:** advanced read surfaces must reuse bounded/stored evidence modes where live actor expansion is unnecessary.
- **Evidence-quality risk:** missing or incomplete evidence must never silently improve a decision.
- **Commercial trust risk:** paid checkout remains paused until the customer evidence pipeline is operationally credible.
- **Unprotected main:** target can move without branch protection; exact candidate freshness remains mandatory.
