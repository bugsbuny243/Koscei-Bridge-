# Repository agent contract

All implementation work in this repository must preserve the current Web3 boundary: **ARVIS is the security-intelligence and evidence engine owned by Koschei Web3.**

Canonical references:

- ARVIS actor/token investigation and evidence behavior: [`ACTOR_INVESTIGATION_ENGINE.md`](./ACTOR_INVESTIGATION_ENGINE.md)
- repository/product naming boundary: [`docs/web3-product-boundary.md`](./docs/web3-product-boundary.md)

## Repository boundary

This repository owns ARVIS-facing Web3 intelligence: wallet/token investigation, creator/deployer attribution, funding and flow analysis, launch/liquidity evidence, actor correlation, persistent actor memory, source-aware evidence and deterministic investigation verdicts.

Koschei Lang and Koschei Sentinel are separate projects. Lang owns hardened language/runtime/authorization work. Sentinel owns model/intelligence work. Do not recreate their runtimes, namespaces or authority models inside this repository.

**Matrix belongs to Koschei Lang, not Koschei Web3.** Do not introduce Matrix as a Web3 module or namespace.

The removed Defense OS / Defense Validation / Execution Proof / execution-containment subsystems are not part of this repository boundary. Do not restore them indirectly through routes, handlers, migrations, workers, Dockerfiles, workflows, documentation or compatibility shims unless the repository boundary is explicitly changed first.

## Permanent frontend/runtime rule

**Next.js is prohibited in Koschei Web3.**

Do not introduce or restore the `next` package, `next.config.*`, `next-env.d.ts`, `.next/`, `NEXT_PUBLIC_*`, or a Next.js build/server/deployment path.

Web/mobile/CLI surfaces are presentation clients and must not become authoritative for evidence classification, investigation verdicts, private keys or privileged authorization.

## ARVIS evidence rules

1. New actor/token investigation work must answer a concrete investigation question defined by the canonical actor engine contract.
2. ARVIS actor and unified Radar verdicts use versioned deterministic rules. Weighted formulas, probabilities and `0–100` final scores are prohibited.
3. `VERIFIED`, `OBSERVED`, `INFERRED` and `UNVERIFIED` evidence levels must remain distinct. `INFERRED` is watch-only; `UNVERIFIED` cannot affect a grade or be presented as verified truth.
4. Serious claims require evidence rows that bind the relevant signature/transaction, slot or chain position, timestamp, source, destination, amount or asset, program/protocol and verification status where those fields exist for the chain.
5. Missing or unsupported evidence must remain missing; do not fabricate certainty.
6. Initial-distribution and holder follow-up on Solana must remain mint-specific/ATA-based. Broad recipient-wide wallet-history scans are prohibited in normal pipelines.
7. Persistent actor memory is durable product state. Raw-event retention must not erase durable actor history.
8. Quota-consuming automatic scans are opt-in and disabled by default. Manual owner scans must not silently enable background scanning.
9. AI may explain evidence and deterministic rules but may not fabricate evidence or become the final verdict authority.
10. A package merely existing or compiling is not proof of production wiring. Production claims require an actual caller -> service/handler -> route/worker/startup path and runtime evidence.

## Stability rules

- Do not modify auth, Neon Auth, sessions, owner cookies, billing/entitlement behavior or verified-wallet implementation unless the task explicitly requires it.
- Do not delete a working ARVIS production path until replacement parity and rollback safety are demonstrated.
- Do not move private keys, seed phrases, custody secrets or signing authority into UI code.
- Preserve source provenance and canonical evidence projection across owner, customer and API surfaces.
- Chain-specific implementation belongs at adapters/data collectors. New core investigation concepts should not unnecessarily hard-code Solana semantics; Solana is the current production domain, not the definition of the whole future product.

Every pull request must state which ARVIS investigation/evidence boundary it changes, which ruleset or contract it preserves or updates, and what evidence demonstrates the change.
