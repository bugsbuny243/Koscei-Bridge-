# Repository agent contract

All Codex and automated implementation work in this repository must begin by reading and referencing [`ACTOR_INVESTIGATION_ENGINE.md`](./ACTOR_INVESTIGATION_ENGINE.md) when touching legacy actor/token investigation behavior. New Security Control Plane work must preserve the evidence-first rules below without treating the legacy Radar as the product boundary.

## Non-negotiable product mission

Koschei Web3 is the market-facing Web3 cybersecurity product. Its target is to fill defensible security gaps across execution integrity, signing defense, infrastructure/node protection, cross-chain trust and evidence-backed containment. The legacy Solana investigation/Radar stack remains a supported security sensor; it does not define the future product boundary.

Koschei Lang and Koschei Sentinel are separate projects. Lang is intended to become a hardened programming/execution foundation for high-security crypto software. Sentinel is intended to become the security-intelligence brain across the crypto ecosystem. Web3 may consume their capabilities through explicit interfaces but must not collapse repository boundaries.

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
3. Missing, malformed, unsupported or mismatched security evidence must never silently become a positive decision.
4. AI may explain evidence or triggered rules but may not fabricate evidence or override deterministic security authority.
5. Do not introduce demo, beta, placeholder, synthetic or fabricated production security outputs.
6. Do not modify auth, Neon Auth, sessions, owner cookies, KOSCH entitlement or verified-wallet implementation unless the user explicitly requests that exact work.
7. Do not delete a legacy production path until its replacement has proven behavioral parity and rollback safety.
8. No production private key, seed phrase, custody secret or signing authority may be moved into UI code or an untrusted integration layer.
9. Side effects that can sign, submit, mint, upgrade, transfer, pause/unpause or mutate privileged state must occur only after the relevant Koschei authorization boundary succeeds.
10. Node Shield live-kernel claims require real compatible-kernel evidence; buildability or simulation alone is not a kernel enforcement proof.

## Legacy actor/Radar rules

1. New actor/token investigation work must answer at least one question from the canonical document's ten-question filter.
2. Actor and unified Radar verdicts use versioned deterministic rules. Weighted formulas, probabilities and `0–100` final scores are prohibited.
3. The owner-facing primary Radar remains the existing manual pipeline until explicitly replaced with proven parity and rollback safety.
4. `INFERRED` evidence is watch-only. `UNVERIFIED` evidence cannot affect a grade or appear as a verified claim.
5. Serious claims require evidence rows with signature, slot, timestamp, source, destination, amount, program and verification status.
6. Initial-distribution and holder follow-up must be mint-specific/ATA-based; recipient-wide full wallet history scans are prohibited in broad pipelines.
7. Actor index history is persistent. Raw-event retention must not delete durable actor memory.
8. Quota-consuming automatic scanning is opt-in and disabled by default. Manual owner scans must never silently enable background workers.

Every pull request must state which product/security boundary it changes and the evidence/authorization rule it preserves or strengthens. Pull requests touching legacy investigation behavior must additionally name the applicable actor/Radar ruleset versions.