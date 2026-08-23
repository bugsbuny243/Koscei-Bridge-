# KOSCHEI WEB3 — ARVIS

Koschei Web3 is an **evidence-first Web3 security-intelligence and investigation platform**. Its implemented engine in this repository is **ARVIS**.

ARVIS investigates wallets, tokens, creators/deployers, funding paths, distribution, liquidity behavior and repeat actors, then projects the evidence through deterministic, versioned rules. The current production domain is Solana; future chain support must be added through explicit chain adapters without redefining the investigation core around one chain.

## Mission

Koschei Web3 answers investigation questions that generic risk cards do not:

- who created or deployed the asset and what funded that actor
- which assets are linked to the same creator, funder or repeat actor
- where the initial distribution went and what happened to those recipients
- whether creator/holder transfers, liquidity events or exit behavior are evidenced on-chain
- which claims are canonically verified, merely observed, inferred or still unverified
- which evidence supports the final deterministic investigation verdict

The product rule is simple:

```text
collect source-aware evidence
            ↓
verify what can be verified
            ↓
build actor / token relationships
            ↓
evaluate deterministic rules
            ↓
publish evidence + verdict
```

Missing evidence stays missing. ARVIS does not manufacture certainty.

## Evidence model

ARVIS keeps four evidence levels distinct:

- `VERIFIED` — independently confirmed by the canonical evidence path
- `OBSERVED` — directly observed but not promoted to canonical verification
- `INFERRED` — derived relationship or hypothesis; watch-only unless independently verified
- `UNVERIFIED` — unsupported or incomplete evidence that cannot affect the final grade

Final investigation grades/verdicts are deterministic and ruleset-versioned. Weighted `0–100` final scores are not the authority model. AI may explain evidence and rules, but it does not create evidence or own the final verdict.

## What exists today

The repository contains a production Go API and worker pipeline with ARVIS investigation and supporting Web3 security surfaces, including:

- live Solana radar and token/wallet investigation
- creator, deployer, funding and actor-linkage intelligence
- initial-distribution and holder-follow-up evidence
- Pump-style launch observations and Raydium-oriented liquidity evidence
- persistent actor memory and repeat-actor correlation
- source-aware evidence collection and canonical ARVIS projection
- signed verdict/evidence contracts
- Token-2022 analysis and transaction-guard compatibility surfaces
- persistent watchlists and HMAC-signed webhook delivery
- authenticated B2B scanning, idempotency, async result lookup and usage accounting
- TypeScript client, schemas, examples and CI checks

Solana is the current production adapter and evidence domain. It is **not** the definition of the future Koschei Web3 universe.

## ARVIS investigation contract

The canonical actor investigation flow is:

```text
wallet / mint / transaction
            ↓
target classification
            ↓
creator / deployer / funding origin
            ↓
created or linked assets
            ↓
initial distribution
            ↓
recipient / holder follow-up
            ↓
liquidity and transfer evidence
            ↓
repeat-actor correlation
            ↓
persistent evidence graph
            ↓
deterministic investigation verdict
```

On Solana, expensive holder follow-up must stay mint-specific and ATA-based. Broad recipient-wide wallet-history scans are not the normal investigation path.

Persistent actor memory is durable product state. Shorter raw-event retention must not erase long-lived actor history.

See `ACTOR_INVESTIGATION_ENGINE.md` for the canonical investigation behavior.

## Current developer routes

```text
POST /api/v1/radar/check        session-authenticated radar check
GET  /api/v1/radar/feed         authenticated verdict feed
POST /api/v1/scan/token         API-key token and batch scan
POST /api/v1/shield/preflight   API-key pre-signing compatibility check
POST /api/v1/shield/transaction API-key transaction-guard compatibility path
GET  /api/v1/usage              API-key usage and async results
GET  /api/v1/risk/badge         public rate-limited evidence/risk badge
```

The `/shield/*` routes are existing compatibility/product surfaces. They do **not** imply that the removed Defense OS, Defense Validation or Execution Proof subsystems are active in this repository.

See `docs/api-reference.md` for route behavior.

## Repository boundary

This repository owns Koschei Web3's ARVIS intelligence/evidence implementation.

The following expansions are **outside the current repository boundary** and must not be silently restored through handlers, routes, workers, migrations, Dockerfiles, workflows, documentation or compatibility shims:

- Defense OS
- Defense Validation
- Execution Proof
- Node Shield
- Web3-native execution-containment runtimes

Koschei Sentinel and Koschei Lang are separate projects with explicit responsibilities. Matrix belongs to Koschei Lang, not Koschei Web3.

See `docs/web3-product-boundary.md` for the canonical ownership boundary.

## Security authority boundary

The user interface is not evidence or verdict authority.

**Next.js is permanently prohibited in Koschei Web3.** Do not introduce the `next` package, Next.js build/server paths, `.next/` output or `NEXT_PUBLIC_*` configuration.

Web, mobile and CLI clients are presentation surfaces. They must not own private keys, fabricate evidence, override canonical evidence classification or replace deterministic ARVIS verdict rules.

## Architecture principle

Chain-specific semantics belong in adapters and collectors. New core investigation concepts should bind to neutral evidence concepts wherever possible, while preserving the exact semantics required by each chain.

The current production architecture includes:

```text
Go API and workers
        ↓
ARVIS investigation services
        ↓
source-aware Solana collectors/adapters
        ↓
Neon PostgreSQL + durable actor memory
        ↓
owner / customer / API evidence projections
```

Secrets and production credentials live only in the deployment environment and are not committed to the repository.

## Local validation

### Go API

```bash
git clone https://github.com/bugsbuny243/Koschei-Web3-Hub.git
cd Koschei-Web3-Hub/koschei/api
go test ./...
go vet ./...
go build ./...
```

### TypeScript SDK

```bash
cd sdk/typescript
npm install
npm run check
npm test
npm pack --dry-run
```

### Event normalizer

```bash
cd oss/event-normalizer
npm install
npm run check
npm test
npm pack --dry-run
```

## Documentation

- Actor investigation engine: `ACTOR_INVESTIGATION_ENGINE.md`
- Web3 product boundary: `docs/web3-product-boundary.md`
- Architecture: `docs/ARCHITECTURE.md`
- Data flow: `docs/architecture/data-flow.md`
- API reference: `docs/api-reference.md`
- Developer quickstart: `docs/DEVELOPER_QUICKSTART.md`
- Signed verdict contract: `docs/signed-verdict-schema.md`
- Limitations: `docs/limitations.md`

## License

MIT — see `LICENSE`.

---

**Koschei Web3 is ARVIS: evidence-first actor, token and on-chain relationship intelligence with deterministic investigation rules.**
