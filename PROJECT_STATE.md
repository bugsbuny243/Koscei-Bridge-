# Koschei Web3 Project State

This file is the authoritative repository checkpoint for continuing Koschei Web3 work across chat/session boundaries. Current repository state wins over conversational assumptions and stale branch history.

## CURRENT STATE

- Current verified `main` head: **`b5f614cfb993a95320dcf339ff1af39e5cdbb51c`**, merge of PR **#983**, `fix(public): fail close stale risk badge`.
- Railway deployed that exact main commit successfully. Production `KOSCHEI_PUBLIC_BADGE_ENABLED` was then deliberately set to `false`; the resulting Railway redeploy also completed successfully.
- Koschei Web3 is a **Solana-first evidence-backed security and risk-intelligence product**. Transaction Guard uses the canonical operator action vocabulary **`allow / warn / block / withhold`**.
- New paid checkout remains paused by default. Polar webhook/renewal/revoke and existing entitlement processing remain intact; server-side entitlements are the only paid-access authority.
- ARVIS remains the active product core and evolves along **Address -> Entity -> Transaction -> Behavior -> Attack Path -> Evidence**.
- Raw `AnalyzeArvisRadarsContext` intentionally starts handler-enriched arms unavailable until callers attach their evidence. A hard-coded unavailable service-layer placeholder is not proof that its collector is absent.
- PR #981 connected Professional Exposure to the existing LP/control evidence chain. PR #982 separated source-only creator attribution from canonically VERIFIED creator evidence. PR #983 made the stale public badge fail closed instead of fabricating a replacement score/verdict.
- `launch_distribution` already exists in Launch Forensics and is attached by canonical customer investigation paths. `repeat_actor_scan` already uses retention-independent persistent actor memory in full canonical investigations. No duplicate collectors are needed.
- Broad stream-verdict workers remain intentionally paused by RPC-saver/background policy; their dormant code still expects the legacy compatibility final and must not be re-enabled until migrated to the canonical unified decision contract.
- Active branch: **`fix/pump-selective-saver-gap`**. Repo audit found a selective Pump ownership dead zone: production canonical worker activity pauses the legacy inline high-volume scanner, while the canonical Pump scheduler also refused to run when broad automatic scanning was disabled or RPC saver was enabled. The branch makes the bounded canonical Pump scheduler the selective exception while preserving the shared RPC budget and per-cycle job cap.
- Koschei Sentinel is cancelled. Koschei Lang is separate and deferred; neither is an active Web3 implementation dependency.
- `main` remains unprotected; exact-head, exact merge-candidate and target-freshness verification are mandatory before merge.

## CHANGED

### PR #981 — Professional Exposure canonical liquidity evidence

Merged and production-deployed:

- `/api/v1/radar/exposure` reuses the canonical unified investigation path instead of the raw ARVIS compatibility path;
- Exposure runs in bounded `exposure_report_stored_only` mode so LP/market evidence is collected without starting broader live actor/funding expansion;
- the liquidity section projects real pool/program/vault/reserve/read-slot/LP-control/liquidity-movement evidence;
- deterministic Unified Radar verdict plus canonical `allow / warn / block / withhold` decision semantics are used;
- evidence can be returned without a signed letter grade and remains `withhold` rather than becoming an approval or server failure;
- shareable Exposure output no longer presents a numeric `/100` final score.

### PR #982 — creator-link provenance integrity

Merged and production-deployed:

- a creator wallet string alone no longer becomes VERIFIED on-chain evidence;
- source-only creator attribution stays OBSERVED/source evidence;
- `verified_canonical_create_*` plus a positive Solana slot is required for `creator_relation_verified=true`, `verified_evidence=true` and `real_onchain_evidence=true`;
- a canonical-looking label without a positive slot fails closed;
- creator-link evidence remains wallet-level technical evidence only and makes no real-world identity/wrongdoing claim;
- regression tests cover OBSERVED source attribution, VERIFIED canonical creator relation and missing-slot fail-closed behavior.

### PR #983 — public badge readiness integrity

Merged and production-deployed:

- `KOSCHEI_PUBLIC_BADGE_ENABLED` defaults disabled and requires explicit opt-in;
- control-plane health reports the same disabled default;
- `.env.example` documents the badge as disabled while no canonical public decision path exists;
- regression tests lock default-disabled behavior, explicit opt-in support and control-plane reporting;
- public API docs no longer advertise stale sample numeric grade/risk-index badge output as a production-ready contract;
- production route documentation distinguishes boot-chain registration from feature readiness;
- production Railway variable was explicitly set to `false` after merge and the redeploy succeeded.

### Active branch — canonical selective Pump under RPC saver

This branch does not add a detector, score or new RPC provider. It repairs worker ownership:

- the canonical Pump high-volume scheduler is no longer blocked by the broad `KOSCHEI_AUTOMATIC_SCANNING_ENABLED` switch or RPC-saver gate;
- `PUMP_HIGH_VOLUME_RADAR_ENABLED` remains the selective high-volume gate;
- only mints crossing the configured 24h USD threshold can enqueue canonical investigations;
- the shared Solana RPC budget remains active in saver mode and the normal per-cycle maximum remains one job by default;
- the legacy inline Pump scanner can remain paused when the canonical investigation worker owns selective deep scans;
- regression tests assert that broad scanning stays off and RPC saver stays on while the explicitly enabled selective Pump scheduler remains eligible, and that `PUMP_HIGH_VOLUME_RADAR_ENABLED=false` fails closed.

## VERIFIED

### PR #981

Exact PR head **`006479438ff374d2e30b9759947a3376a837d3fc`** passed all permanent workflows before merge, including PostgreSQL migrations/retention, full Go tests, race, vet, build, security scans, exact merge-candidate verification and target freshness. It merged as **`a84c5406c40f409b9f1717c4581a7fdbc19d9d4d`** and deployed successfully.

### PR #982

Exact PR head **`4ccf17a435ef9dc32c3f99fdb66ba426aeb163a3`** passed all observed permanent workflows, including API Required, Public Product Smoke, Auth Freeze, Security CI, CodeQL, Supply Chain, Operator Exit and Release Gates. It merged as **`6b8d344a6d6aad86c3d0e981731a98af67fe4591`** and deployed successfully.

### PR #983

Exact PR head **`2b9fbc7190455a1ab9e61ef0fce3a0364932a31d`** passed all nine observed permanent workflows:

- Runtime Control Plane Smoke;
- Auth Freeze Guard;
- Public Product Smoke;
- Security CI;
- Supply Chain Security;
- CodeQL;
- API Required CI;
- Operator Exit Corpus Acceptance;
- Release Gates Verification.

Release/API verification included gofmt, PostgreSQL 17 migrations/retention, public-language/contracts, full Go tests, race, vet, build, secret/vulnerability/static scans, exact merge-candidate verification and target freshness.

PR #983 merged as **`b5f614cfb993a95320dcf339ff1af39e5cdbb51c`**. Railway deployed the merged commit successfully. `KOSCHEI_PUBLIC_BADGE_ENABLED=false` was then applied explicitly in production and the resulting redeploy also succeeded.

### Pump selective repo truth

Verified by current code inspection:

- `main.go` explicitly states that RPC saver pauses broad Solana streams while explicitly enabled selective workers may remain active;
- `SolanaRPCLimitSaverEnabled` defaults true in production and the shared RPC budget defaults to 220 requests/hour in saver mode;
- `StartPumpPortalRadarIfEnabled` pauses the legacy inline high-volume scanner when the canonical investigation worker is active;
- before this branch, `StartCanonicalPumpJobScheduler` simultaneously required broad automatic scanning and `!SolanaRPCLimitSaverEnabled`, producing a dead zone in the documented production selective configuration;
- canonical Pump jobs run `buildUnifiedInvestigationReport`, persist the canonical Unified Radar verdict and reuse the same Launch Forensics/persistent repeat-actor evidence path as customer investigations;
- `jobs.Store.CreateUniqueActive` deduplicates the same Pump bucket across queued, running and completed jobs, preventing duplicate deep canonical investigations within the same dedupe bucket.

### Active branch verification

Pending CI. Do not merge or call the selective Pump saver-gap repair production-verified until the exact branch head passes permanent gates.

## BROKEN / MISSING

- Active selective-Pump branch still requires exact-head CI, exact merge-candidate and target-freshness verification.
- `PumpHighVolumeReportedRecently` still checks the retired signed `final_verdict_engine` row in `security_radar_verdicts`. Canonical job dedupe prevents duplicate deep scans inside the same bucket, but this stale helper can still create redundant observation/attempt bookkeeping and should be migrated to canonical completion evidence separately.
- Owner Pump fast-report projection also joins the retired `final_verdict_engine` and can leave canonical reports displayed as `evidence_pending`; it must be migrated without reintroducing a fake numeric risk score.
- Dormant broad stream-verdict worker still depends on `ArvisFinalFromBundle(...).Signed` and cannot be safely re-enabled until it consumes the same canonical actor/behavior inputs as full investigations.
- Public badge has no canonical low-cost public decision path yet. Keep it disabled; do not re-enable it by translating compatibility fields into a fake decision.
- Creator-link arm still does not carry the exact canonical create transaction signature end-to-end; current Launch Forensics projection carries the verified slot/source anchor but not that signature. Do not invent one.
- A Solana adversarial fixture set is still missing for fake LP-lock claims, false creator attribution, ATA/freeze surprises, Token-2022 transfer-hook injection, authority mutation, wrong mint/account resolution and incomplete state evidence.
- Exact approved-instruction-set vs candidate-instruction-set binding is not complete; Transaction Guard v3 already has signed UI intent, decoding, state witness and enforcement-permit primitives that should be extended rather than replaced.
- Anonymous `/dashboard` still needs a cleaner login-first boundary without fake sample data.
- `/feedback` still contains legacy Turkish source copy even though primary customer surfaces are English.
- `tradepigloball.co` remains a brand-trust liability; no domain migration should be faked before a real Koschei domain is selected and controlled.
- A real paid Polar payment -> signed webhook -> provider event ledger -> entitlement activation cycle has not yet been proven in production.

## NEXT

1. Run the exact selective-Pump branch through permanent CI; repair failures on the same branch.
2. Merge only after exact merge-candidate and target-freshness gates pass, then verify merged `main` and Railway production deployment.
3. Verify production logs show the canonical Pump selective scheduler active while broad RPC workers remain paused under saver mode.
4. Migrate Pump report cooldown and owner fast-report projection from legacy `final_verdict_engine` assumptions to canonical job/unified-verdict evidence without manufacturing numeric scores.
5. Keep broad stream verdicts disabled until they can consume the same canonical unified actor/behavior decision inputs as manual investigations.
6. Add adversarial Solana fixtures that try to break Koschei's evidence claims.
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
- No duplicate LP/liquidity, creator, launch-distribution or repeat-actor collector when canonical evidence already exists.
- No new final-verdict engine inside background workers just to make legacy code green.
- No revival of the legacy inline Pump scanner as the primary production path while the canonical job path exists.
- No EVM-first rewrite and no promotion of Safe/Anvil executionproof to the product spine.
- No new paid checkout while commercial readiness remains paused.
- No revival of Paddle or KOSCH/token-backed commercial authorization.
- No Koschei Sentinel implementation/integration target.
- No Koschei Lang implementation inside this repository.
- No broad multi-chain abstraction before the Solana evidence/decision contract is production-coherent.

## RISKS

- **Selective-worker ownership risk:** a canonical worker can suppress a legacy worker while its own scheduler is blocked by an unrelated broad-scan gate, silently creating coverage gaps.
- **RPC-cost risk:** selective Pump must remain thresholded, deduplicated, per-cycle bounded and subject to the shared RPC budget even when broad saver mode is active.
- **Decision drift risk:** legacy `final_verdict_engine` storage assumptions remain in Pump cooldown/owner telemetry and must not be treated as canonical final authority.
- **Public-contract risk:** a registered route can look production-ready even when its canonical decision contract is unavailable; public badge therefore remains disabled.
- **Creator-provenance risk:** source attribution must never be presented as canonical on-chain verification merely because a creator wallet string exists.
- **Evidence-routing risk:** working collectors can appear missing when a caller bypasses their attachment stage; inspect route truth before inventing duplicate intelligence.
- **Evidence-quality risk:** missing or incomplete evidence must never silently improve a decision.
- **Commercial trust risk:** paid checkout remains paused until the customer evidence pipeline is operationally credible.
- **Unprotected main:** target can move without branch protection; exact candidate freshness remains mandatory.
