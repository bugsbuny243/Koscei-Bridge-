# Repository agent contract

All Codex and automated implementation work in this repository must select the applicable canonical contract before changing behavior:

- product-wide defense validation and Security Control Plane work: [`WEB3_DEFENSE_VALIDATION_ENGINE.md`](./WEB3_DEFENSE_VALIDATION_ENGINE.md);
- ARVIS actor/token investigation and evidence behavior: [`ACTOR_INVESTIGATION_ENGINE.md`](./ACTOR_INVESTIGATION_ENGINE.md);
- repository/product naming boundary: [`docs/web3-product-boundary.md`](./docs/web3-product-boundary.md).

Work that crosses these surfaces must preserve their separate authority models. ARVIS Radar/Actor evidence may inform a validation scenario, but it cannot self-produce a defense-validation result.

## Non-negotiable product mission

Koschei Web3 is the market-facing Web3 cybersecurity product. Its target is to fill defensible security gaps across on-chain intelligence, investigation, execution integrity, signing defense, infrastructure/node protection, cross-chain trust, monitoring and evidence-backed defense validation.

**ARVIS is a core intelligence and evidence engine inside Koschei Web3.** ARVIS is not a legacy subsystem, retired product, separate product family or temporary compatibility layer. Its Radar, actor/token investigation, source-aware evidence, funding/flow, creator/deployer, liquidity, launch and transaction-intelligence capabilities remain first-class Web3 capabilities. ARVIS does not define the entire Koschei Web3 product boundary by itself, but it is an integral engine inside that boundary.

The product-wide validation question is: **does this exact Web3 defense configuration actually catch or contain this controlled attack before impact without flagging the matched benign action?** Defense-validation outcomes are deterministic `VALIDATED`, `FAILED` or `INCOMPLETE` results scoped to exact configuration/scenario/evidence identity. They do not replace ALLOW/BLOCK authorization decisions at signing or containment boundaries.

Koschei Lang and Koschei Sentinel are separate projects. Lang is intended to become a hardened programming/execution foundation for high-security crypto software. Sentinel is intended to become the security-intelligence brain across the crypto ecosystem. Web3 may consume their capabilities through explicit interfaces but must not collapse repository boundaries.

**Matrix belongs to Koschei Lang, not Koschei Web3.** Do not introduce Matrix as a Web3 product module, customer-facing capability, architecture layer, containment engine or namespace. Web3-native deterministic containment uses the `internal/executioncontainment` namespace. Future Lang/Matrix integration must arrive through an explicit cross-project interface rather than by moving Matrix into this repository.

## Permanent frontend/runtime rule

**Next.js is prohibited in Koschei Web3.**

Do not introduce or restore:

- the `next` package or any Next.js dependency;
- `next.config.*`, `next-env.d.ts` or `.next/` build output;
- `NEXT_PUBLIC_*` environment variables;
- Next.js server/runtime/build/deployment paths;
- a Next.js frontend, even as a presentation-only option.

Web/mobile/CLI surfaces are untrusted presentation clients. They must never become authoritative for signing decisions, Execution Proof, policy grants, private keys, bridge/validator authority, Node Shield policy, or Sentinel decisions.

## Non-negotiable security rules

1. New Security Control Plane work is evidence-first, deterministic where possible, and fail-closed at authority boundaries.
2. Execution/signing authorization must use explicit ALLOW/BLOCK semantics; no numeric risk score, weighted formula or AI-generated authority decision may replace verified evidence.
3. Defense validation must use exact attack + benign-control coverage, independently collected evidence and versioned deterministic rules. Attack-only or vendor-self-attested validation is incomplete.
4. Missing, malformed, unsupported or mismatched security evidence must never silently become a positive decision.
5. A package existing or compiling in `main` is not proof that it is production-wired. Production claims require a verified caller -> service/handler -> route/worker/startup path, explicit gate ownership, integration coverage and runtime evidence.
6. AI may explain evidence or triggered rules but may not fabricate evidence, override deterministic security authority or produce a defense-validation verdict.
7. Do not introduce demo, beta, placeholder, synthetic or fabricated production security outputs. Planned scenarios must be explicitly non-evidentiary until real execution and observation evidence exists.
8. Controlled validation must not store wallet material, submit mainnet transactions, mutate tested production controls, accept arbitrary commands or enable autonomous intervention.
9. Do not modify auth, Neon Auth, sessions, owner cookies, KOSCH entitlement or verified-wallet implementation unless the user explicitly requests that exact work.
10. Do not delete an established production path until its replacement has proven behavioral parity and rollback safety.
11. No production private key, seed phrase, custody secret or signing authority may be moved into UI code or an untrusted integration layer.
12. Side effects that can sign, submit, mint, upgrade, transfer, pause/unpause or mutate privileged state must occur only after the relevant Koschei authorization boundary succeeds.
13. Node Shield live-kernel claims require real compatible-kernel evidence; buildability or simulation alone is not a kernel enforcement proof.
14. `internal/executionproof` remains non-production-wired until the #864 connectivity acceptance conditions are satisfied. Do not create a blind signing/forwarding dependency merely to demonstrate integration.

## ARVIS actor/Radar rules

1. New ARVIS actor/token investigation work must answer at least one question from the canonical document's ten-question filter.
2. ARVIS actor and unified Radar verdicts use versioned deterministic rules. Weighted formulas, probabilities and `0–100` final scores are prohibited.
3. The owner-facing primary ARVIS Radar remains the existing manual pipeline until explicitly replaced with proven parity and rollback safety.
4. `INFERRED` evidence is watch-only. `UNVERIFIED` evidence cannot affect a grade or appear as a verified claim.
5. Serious claims require evidence rows with signature, slot, timestamp, source, destination, amount, program and verification status.
6. Initial-distribution and holder follow-up must be mint-specific/ATA-based; recipient-wide full wallet history scans are prohibited in broad pipelines.
7. ARVIS actor index history is persistent. Raw-event retention must not delete durable actor memory.
8. Quota-consuming automatic scanning is opt-in and disabled by default. Manual owner scans must never silently enable background workers.

Every pull request must state which product/security boundary it changes and the evidence/authorization rule it preserves or strengthens. Defense-validation PRs must state whether they change scenario, execution, observation, evaluation, publication or production-enforcement authority and list the safety gates preserved. Pull requests touching ARVIS investigation behavior must additionally name the applicable actor/Radar ruleset versions.
