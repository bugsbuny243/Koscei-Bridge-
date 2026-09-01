# Koschei Web3 Project State

This file is the authoritative repository checkpoint for continuing Koschei Web3 work across chat/session boundaries. Current repository state wins over conversational assumptions and stale branch history.

## CURRENT STATE

- Current verified `main` head: **`b7d4729df167f9ae4592002c0892673c2c2bc022`**, merge of PR **#984**, `fix(pump): preserve selective canonical coverage in saver mode`.
- Railway deployed that exact commit successfully in production.
- Production runtime proves broad Solana/Radar RPC workers are paused by RPC saver while the canonical investigation job worker remains active.
- PumpPortal discovery, durable inbox/trade ledger and websocket ingestion are active in production.
- The canonical Pump selective scheduler did **not** emit its startup log after #984. Production therefore must not be represented as actively running selective Pump deep scans yet; the explicit `PUMP_HIGH_VOLUME_RADAR_ENABLED` setting remains an operator decision after canonical report-state repair is deployed.
- Public risk badge remains deliberately fail-closed. `KOSCHEI_PUBLIC_BADGE_ENABLED=false` was explicitly applied in production after PR #983 and the redeploy succeeded.
- Koschei Web3 remains a **Solana-first evidence-backed security and risk-intelligence product**. Transaction Guard uses the canonical operator vocabulary **`allow / warn / block / withhold`**.
- ARVIS remains the product core and evolves along **Address -> Entity -> Transaction -> Behavior -> Attack Path -> Evidence**.
- New paid checkout remains paused by product-readiness policy. Polar webhook/renewal/revoke and server-side entitlement handling remain intact; a real production payment -> signed webhook -> entitlement activation cycle is still unproven.
- Broad legacy stream-verdict workers remain intentionally disabled until migrated away from compatibility-final assumptions.
- Active branch: **`fix/pump-canonical-report-state`**. It moves selective Pump completion/cooldown and owner telemetry from retired `final_verdict_engine` assumptions to the canonical investigation job ledger/result payload.
- Koschei Sentinel is cancelled. Koschei Lang is separate and deferred; neither is an active Web3 implementation dependency.
- `main` remains unprotected; exact-head, exact merge-candidate and target-freshness verification are mandatory before merge.

## CHANGED

### PR #983 — public badge readiness integrity

Merged and production-deployed:

- public badge defaults disabled and requires explicit opt-in;
- control-plane health and docs reflect the same fail-closed readiness state;
- stale numeric public-badge examples are no longer presented as a production contract;
- production `KOSCHEI_PUBLIC_BADGE_ENABLED=false` was applied explicitly and redeployed successfully.

### PR #984 — selective canonical Pump coverage under RPC saver

Merged and production-deployed:

- the canonical Pump high-volume scheduler is a bounded selective exception to broad automatic-scanning/RPC-saver gates;
- `PUMP_HIGH_VOLUME_RADAR_ENABLED` remains the explicit selective feature gate;
- only mints crossing the configured 24h USD threshold may enqueue canonical investigations;
- shared Solana RPC budgeting, canonical job dedupe and the normal one-job-per-cycle default remain intact;
- the legacy inline Pump scanner remains paused while the canonical investigation worker owns deep investigation;
- regression tests lock saver-mode eligibility and fail-closed explicit disable semantics.

### Active branch — canonical Pump report state

This branch does not add a detector, score, provider or new chain collector. It repairs evidence authority:

- canonical Pump report cooldown now checks a **completed canonical investigation job** with exact source/mode/target binding instead of a signed legacy `final_verdict_engine` row;
- Solana mint matching is exact and case-sensitive;
- scheduler source/mode constants are shared with the completion query to prevent string drift;
- owner `/api/owner/arvis` Pump projection reads the latest matching canonical job and its own `result_payload.final_verdict`;
- legacy numeric `risk_index` is not projected as canonical Pump report state;
- worker completion and verdict signing are separated: an unsigned completed job is reported as **`completed_unsigned`**, not as a signed verdict;
- canonical job ID/status/error, ruleset, decision path and signature provenance are projected where available;
- the owner fast overview removes the parallel legacy final-verdict representative for mints already represented by canonical high-volume Pump state, preventing old frontend merge logic from restoring stale `signed=true` fields;
- PostgreSQL regression coverage proves a legacy signed final cannot satisfy canonical cooldown or owner completion, and proves unsigned vs signed canonical completion semantics;
- unit coverage proves legacy Pump filtering preserves exact Solana case semantics.

## VERIFIED

### PR #983

Exact PR head **`2b9fbc7190455a1ab9e61ef0fce3a0364932a31d`** passed all observed permanent workflows, including Runtime Control Plane Smoke, API Required, Release Gates, CodeQL, Security CI, Supply Chain, Auth Freeze, Public Product and Operator Exit. It merged as **`b5f614cfb993a95320dcf339ff1af39e5cdbb51c`** and production redeploys succeeded.

### PR #984

Final exact PR head **`d55d9b6f3e3353e3622fa3ebeb3384baef4203f6`** passed all eight permanent workflows after an older contradictory RPC-saver regression test was updated on the same branch. Verification included:

- full Go tests;
- gofmt;
- PostgreSQL 17 migrations/retention;
- race tests;
- vet and build;
- CodeQL, secret/vulnerability/static scans and supply-chain gates;
- exact merge-candidate verification;
- target-base freshness.

PR #984 merged as **`b7d4729df167f9ae4592002c0892673c2c2bc022`** and Railway deployment **`1c9b35a9-dc96-40f2-965f-7404cd96ec2a`** succeeded.

### Production runtime after #984

Observed in Railway startup logs:

- `broad security radar RPC workers paused: SOLANA_RPC_LIMIT_SAVER_ENABLED=true; manual scans remain available`;
- `broad Solana streams paused: RPC saver protects quota; explicitly enabled selective workers may remain active`;
- `canonical investigation job worker started ... concurrency=1`;
- PumpPortal discovery/durable inbox/websocket started successfully.

No `canonical pump selective scheduler started` line was observed. Do not claim production selective Pump deep scanning is enabled yet.

### Active branch verification

Code and regression tests are committed but permanent CI has not run yet. Do not merge or call the branch production-verified until its exact head passes all required workflows.

## BROKEN / MISSING

- Active `fix/pump-canonical-report-state` branch still requires exact-head CI, exact merge-candidate and target-freshness verification.
- Production selective Pump scheduler is not currently evidenced as started. Do not blindly enable it before this branch is merged/deployed and bounded runtime behavior is ready to observe.
- The dormant **legacy inline Pump worker** still calls the old `PumpHighVolumeReportedRecently` helper that checks `final_verdict_engine`. That worker is not the intended production path while the canonical worker owns investigations; remove/migrate this debt separately rather than reviving it.
- The older non-fast `LatestPumpHighVolumeReports` path still contains a legacy final-engine join. The registered `/api/owner/arvis` route uses the repaired fast projection; legacy/non-primary telemetry should be cleaned separately.
- Broad stream-verdict worker still depends on `ArvisFinalFromBundle(...).Signed` compatibility behavior and must remain disabled until canonical actor/behavior decision inputs are used.
- Public badge has no canonical low-cost public decision path. Keep it disabled.
- Creator-link evidence still lacks the exact canonical create transaction signature end-to-end; slot/source provenance exists, but no signature should be invented.
- Adversarial Solana fixtures are still missing for fake LP-lock claims, false creator attribution, ATA/freeze surprises, Token-2022 transfer-hook injection, authority mutation, wrong account/mint resolution and incomplete state evidence.
- Exact approved-instruction-set vs candidate-instruction-set binding is not complete; extend Transaction Guard v3 signed intent + decoding + state witness + enforcement permit rather than replacing it.
- Anonymous `/dashboard` needs a cleaner login-first boundary without fake data.
- `/feedback` still contains legacy Turkish source copy while primary customer surfaces are English.
- `tradepigloball.co` remains a brand-trust liability until a real Koschei domain is selected and controlled.
- A real production Polar payment -> signed webhook -> provider ledger -> entitlement activation cycle has not yet been proven.

## NEXT

1. Open the canonical Pump report-state PR and run the exact branch head through all permanent CI gates.
2. Repair any failure on the same branch; do not branch-hop.
3. Merge only after exact merge-candidate and target-freshness gates pass.
4. Verify merged `main` and Railway production deployment.
5. After deployment, explicitly decide whether to set `PUMP_HIGH_VOLUME_RADAR_ENABLED=true`; if enabled, retain saver mode, shared RPC budget, thresholding and one-job-per-cycle default, then verify scheduler startup/cycle logs and RPC behavior.
6. Clean the dormant legacy Pump cooldown/non-fast telemetry debt without reintroducing numeric scores.
7. Move product work to adversarial Solana evidence fixtures and exact Transaction Guard instruction-intent binding.

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
- No revival of the legacy inline Pump scanner as the primary production path.
- No EVM-first rewrite and no promotion of Safe/Anvil execution proof to the product spine.
- No new paid checkout while commercial readiness remains paused.
- No revival of Paddle or KOSCH/token-backed commercial authorization.
- No Koschei Sentinel implementation/integration target.
- No Koschei Lang implementation inside this repository.
- No broad multi-chain abstraction before the Solana evidence/decision contract is production-coherent.

## RISKS

- **Evidence-authority risk:** a completed worker job, a signed verdict and a legacy compatibility-final row are different facts and must never be collapsed into one state.
- **Frontend merge risk:** parallel legacy signed rows can silently overwrite canonical unsigned state unless the server exposes one authoritative Pump projection.
- **RPC-cost risk:** selective Pump must remain explicitly enabled, thresholded, deduplicated, per-cycle bounded and subject to the shared RPC budget.
- **Decision-drift risk:** dormant legacy final assumptions can become unsafe if old workers or telemetry are reactivated without canonical migration.
- **Public-contract risk:** registered surfaces can look production-ready even when canonical decision evidence is unavailable; public badge therefore remains disabled.
- **Creator-provenance risk:** source attribution must never be presented as canonical on-chain verification merely because a creator wallet string exists.
- **Evidence-quality risk:** missing or incomplete evidence must never silently improve a decision.
- **Commercial trust risk:** paid checkout remains paused until the customer evidence pipeline is operationally credible.
- **Unprotected main:** target can move without branch protection; exact candidate freshness remains mandatory.
