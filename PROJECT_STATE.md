# Koschei Web3 Project State

This file is the authoritative repository checkpoint for continuing Koschei Web3 work across chat/session boundaries. Current repository state wins over conversational assumptions and stale branch history.

## CURRENT STATE

- Current verified `main` head: **`6b8d344a6d6aad86c3d0e981731a98af67fe4591`**, merge of PR **#982**, `fix(arvis): preserve creator relation provenance`.
- Railway deployed that exact main commit successfully. Public API transport `/health` and public product `/scan` statuses are successful.
- Koschei Web3 is a **Solana-first evidence-backed security and risk-intelligence product**. Transaction Guard uses the canonical operator action vocabulary **`allow / warn / block / withhold`**.
- New paid checkout remains paused by default. Polar webhook/renewal/revoke and existing entitlement processing remain intact; server-side entitlements are the only paid-access authority.
- ARVIS remains the active product core and evolves along **Address -> Entity -> Transaction -> Behavior -> Attack Path -> Evidence**.
- Raw `AnalyzeArvisRadarsContext` intentionally starts handler-enriched arms unavailable until callers attach their evidence. A hard-coded unavailable service-layer placeholder is not proof that its collector is absent.
- PR #981 connected Professional Exposure to the existing LP/control evidence chain. PR #982 separated source-only creator attribution from canonically VERIFIED creator evidence.
- `launch_distribution` repo audit is complete: the collector/arm already exists in Launch Forensics and is attached by the canonical customer Check/Detail investigation path and by the selective Pump high-volume worker. No new launch-distribution collector is needed.
- `repeat_actor_scan` repo audit is partially complete: the full customer investigation path already loads persistent repeat-dominant holder memory and applies it to the arm. The selective Pump high-volume worker does not currently attach that stored actor memory.
- Broad stream-verdict workers are intentionally paused in production by RPC-saver/background flags. Their dormant code still expects the legacy compatibility final and must not be re-enabled until migrated to the canonical unified verdict contract.
- Public risk badge route is registered and rate-limited, but its handler still consumes the unsigned compatibility final. It must not be represented as production-ready. Active branch **`fix/public-badge-readiness`** changes its runtime default to disabled/explicit opt-in and removes stale numeric public-badge documentation.
- Railway production contains a `KOSCHEI_PUBLIC_BADGE_ENABLED` variable name, but the connected OAuth view redacts its value. Do not infer whether the current deployment explicitly enables or disables it.
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

### Active branch — public badge readiness integrity

This branch does not create a new badge verdict engine. It prevents an unready surface from defaulting to live:

- `KOSCHEI_PUBLIC_BADGE_ENABLED` runtime default changes from enabled to disabled;
- control-plane health reports the same disabled default;
- `.env.example` documents public badge as explicit opt-in;
- runtime tests lock disabled-by-default behavior, explicit opt-in support and control-plane reporting;
- public API documentation no longer advertises sample `grade` / numeric `risk_index` / signed badge output as a current production contract;
- production route documentation distinguishes boot-chain registration from feature/readiness availability.

## VERIFIED

### PR #981

Exact PR head **`006479438ff374d2e30b9759947a3376a837d3fc`** passed all permanent workflows before merge, including PostgreSQL migrations/retention, full Go tests, race, vet, build, security scans, exact merge-candidate verification and target freshness. It merged as **`a84c5406c40f409b9f1717c4581a7fdbc19d9d4d`** and deployed successfully.

### PR #982

Exact PR head **`4ccf17a435ef9dc32c3f99fdb66ba426aeb163a3`** passed all eight observed permanent workflows:

- API Required CI;
- Public Product Smoke;
- Auth Freeze Guard;
- Security CI;
- CodeQL;
- Supply Chain Security;
- Operator Exit Corpus Acceptance;
- Release Gates Verification.

Release verification included gofmt, PostgreSQL 17 migration/retention checks, full Go tests, race tests, vet, build, exact merge-candidate verification and target freshness.

PR #982 merged as **`6b8d344a6d6aad86c3d0e981731a98af67fe4591`**. Railway deployment, public API transport and public product status all reported success for that merged commit.

### Launch/repeat-actor repo truth

Verified by current code inspection:

- `/api/v1/radar/detail` is routed to `SecurityRadarDetailV3`, which calls `buildUnifiedInvestigationReport(..., "manual_detail")`; the older raw-detail handler is not the registered customer route;
- `ApplyLaunchForensicsToAnalysis` already replaces `launch_distribution`, Pump launch behavior and sniper timing arms with mint-specific ATA/live-ledger evidence;
- selective Pump high-volume analysis also invokes `AnalyzeLaunchForensics` and `ApplyLaunchForensicsToAnalysis`;
- `runHolderIntelligenceCore` already captures holder snapshots, queries persistent repeat-dominant memory and applies `repeat_actor_scan` evidence on canonical full investigations;
- broad stream-verdict worker still calls `ArvisFinalFromBundle`, which intentionally returns an unsigned compatibility final after the Solana-centered decision refactor; production background flags currently keep that broad worker dormant.

### Active branch verification

Pending CI. Do not merge or call the public-badge readiness changes production-verified until the exact branch head passes permanent gates.

## BROKEN / MISSING

- Active public-badge readiness branch still requires exact-head CI, exact merge-candidate and target-freshness verification.
- Production explicitly defines the `KOSCHEI_PUBLIC_BADGE_ENABLED` variable name but its value is redacted by the connected Railway OAuth view. After the code change is merged, set it deliberately to `false` before claiming production badge is disabled.
- Public badge has no canonical low-cost public decision path yet. Do not re-enable it by simply translating compatibility fields into `allow / warn / block / withhold`.
- Selective Pump high-volume worker does not attach persistent repeat-actor memory even though the customer investigation path does.
- Selective Pump report cooldown still looks for a signed `final_verdict_engine` record while modern ARVIS evidence arms no longer manufacture that legacy final. This can cause a qualifying mint to be re-enriched after the shorter attempt cooldown rather than the intended report cooldown.
- Dormant broad stream-verdict worker still depends on `ArvisFinalFromBundle(...).Signed` and therefore cannot be safely re-enabled until it uses the same canonical actor/behavior decision inputs as the full investigation.
- Creator-link arm still does not carry the exact canonical create transaction signature end-to-end; current Launch Forensics projection carries the verified slot/source anchor but not that signature. Do not invent one.
- A Solana adversarial fixture set is still missing for fake LP-lock claims, false creator attribution, ATA/freeze surprises, Token-2022 transfer-hook injection, authority mutation, wrong mint/account resolution and incomplete state evidence.
- Exact approved-instruction-set vs candidate-instruction-set binding is not complete; Transaction Guard v3 already has signed UI intent, decoding, state witness and enforcement-permit primitives that should be extended rather than replaced.
- Anonymous `/dashboard` still needs a cleaner login-first boundary without fake sample data.
- `/feedback` still contains legacy Turkish source copy even though primary customer surfaces are English.
- `tradepigloball.co` remains a brand-trust liability; no domain migration should be faked before a real Koschei domain is selected and controlled.
- A real paid Polar payment -> signed webhook -> provider event ledger -> entitlement activation cycle has not yet been proven in production.

## NEXT

1. Run the exact public-badge readiness branch through permanent CI; repair failures on the same branch.
2. Merge only after exact merge-candidate and target-freshness gates pass, then verify merged `main` and Railway deployment.
3. Explicitly set production `KOSCHEI_PUBLIC_BADGE_ENABLED=false` and verify the redeploy before claiming the public badge is disabled.
4. Fix the selective Pump high-volume path next: reuse persistent repeat-actor memory and repair cooldown semantics without manufacturing a legacy final verdict.
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
- No duplicate LP/liquidity, creator or launch-distribution collector when canonical evidence already exists.
- No new final-verdict engine inside background workers just to make legacy tests green.
- No EVM-first rewrite and no promotion of Safe/Anvil executionproof to the product spine.
- No new paid checkout while commercial readiness remains paused.
- No revival of Paddle or KOSCH/token-backed commercial authorization.
- No Koschei Sentinel implementation/integration target.
- No Koschei Lang implementation inside this repository.
- No broad multi-chain abstraction before the Solana evidence/decision contract is production-coherent.

## RISKS

- **Public-contract risk:** a registered/default-enabled route can look production-ready even when its decision contract cannot produce the canonical signed result.
- **Creator-provenance risk:** source attribution must never be presented as canonical on-chain verification merely because a creator wallet string exists.
- **Evidence-routing risk:** working collectors can appear missing when a caller bypasses their attachment stage; inspect route truth before inventing duplicate intelligence.
- **Background-decision risk:** dormant workers still carrying legacy final assumptions can become unsafe or permanently unavailable if re-enabled without canonical actor/behavior inputs.
- **RPC-cost risk:** stale Pump report-cooldown semantics can repeat expensive enrichment more frequently than intended.
- **Liquidity-proof risk:** market depth alone does not prove LP control or add/remove behavior; transaction-backed movement and on-chain pool/vault evidence must remain distinct.
- **Evidence-quality risk:** missing or incomplete evidence must never silently improve a decision.
- **Commercial trust risk:** paid checkout remains paused until the customer evidence pipeline is operationally credible.
- **Unprotected main:** target can move without branch protection; exact candidate freshness remains mandatory.
