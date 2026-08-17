# KOSCHEI WEB3

Koschei Web3 is being built as a **Web3 security platform**: infrastructure that helps wallets, protocols, exchanges, bridges, validators, security teams and developers prove what is about to execute, detect hostile conditions, and stop unsafe actions before they become irreversible on-chain losses.

The current production system is Solana-native and remains the first proving ground. The product direction is broader: **multi-chain execution integrity, signing safety, infrastructure defense and machine-readable security evidence**.

## Mission

Koschei Web3 exists to fill security gaps that remain between code review, wallet signing, infrastructure operation and final on-chain execution.

The long-term product boundary is:

```text
untrusted UI / wallet / operator surface
                ↓
      Koschei Web3 control plane
                ↓
   execution + signing verification
                ↓
 infrastructure / node / chain defense
                ↓
 evidence-backed allow / warn / block
```

Koschei Web3 is the product layer. Koschei Sentinel is intended to become the security-intelligence brain behind the ecosystem, while Koschei Lang is intended to provide hardened execution and authority primitives for high-security software. These are separate projects with explicit boundaries.

## What exists today

The current live system provides a real Solana-native security foundation:

- production Go API and worker pipeline
- evidence-backed radar and signed verdict contract
- Token-2022 scanner and transaction firewall
- persistent watchlists and HMAC-signed webhook delivery
- authenticated B2B batch screening with idempotency
- asynchronous result lookup and usage accounting
- TypeScript client, schemas, examples and CI checks
- pre-signing transaction and token risk analysis

This existing Solana stack is not being discarded. It is the first operational security domain on top of which broader Web3 security capabilities can be proven.

## Product direction

Koschei Web3 is moving from a narrow risk-intelligence hub toward four security planes:

### 1. Execution Integrity

Goal: independently prove that the transaction, payload, calldata or serialized instruction a user or operator is about to sign is the intended artifact.

Target capabilities include:

- canonical payload reconstruction
- byte-level comparison
- pre-signing simulation
- policy-bound execution approval
- deterministic evidence records
- explicit mismatch blocking

### 2. Signing Defense

Goal: reduce the chance that a compromised UI, developer machine, RPC path or integration can trick a signer into authorizing a different action.

Target capabilities include:

- human-readable intent vs serialized payload verification
- signer-side evidence bundles
- independent transaction reconstruction
- policy-aware allow / warn / block decisions
- replay and mutation detection

### 3. Infrastructure Defense

Goal: protect the systems that produce, relay, validate and execute Web3 actions.

Target domains include:

- RPC integrity
- validator / node health and hostile-state detection
- deployment authorization integrity
- bridge and privileged-operation monitoring
- supply-chain and operator-path evidence

### 4. Cross-chain Security Evidence

Goal: normalize security evidence across chains without pretending every chain has the same trust model.

Solana remains the current production domain. Future chain support must preserve chain-specific semantics instead of flattening them into a generic score.

## Product rule

```text
evidence first
      ↓
independent verification
      ↓
policy evaluation
      ↓
allow / warn / block / withhold
```

No verified evidence means no fabricated certainty.

A low-risk result is not a guarantee of safety. Missing or unsupported evidence must remain missing or withheld rather than silently becoming a positive score.

## Security authority boundary

The user interface is **not** a security authority.

A web frontend may be implemented with Next.js, vanilla JavaScript, another framework, or a native client. That choice must not change the trust model.

The frontend must not become authoritative for:

- final allow / block decisions
- signer private keys
- canonical execution artifacts
- security policy grants
- privileged deployment authorization
- Sentinel security decisions
- bridge, validator or protocol authority

The UI renders decisions and evidence produced by trusted security services. It does not define them.

```text
Next.js / web / mobile / CLI
          │
          │ untrusted presentation
          ▼
Koschei Web3 trusted services
          │
          ├── execution verification
          ├── signing defense
          ├── evidence collection
          ├── policy evaluation
          └── infrastructure defense
```

## Current Solana security core

The existing ARVIS implementation remains an internal/current product capability for Solana security analysis.

Current evidence includes:

- Solana transaction instructions and account relationships
- SPL Token and Token-2022 authorities and extensions
- mint and freeze authority evidence
- program-specific relations and liquidity activity
- priority-fee and pre-signing simulation context
- Pump-style launch observations
- Raydium-oriented liquidity evidence

The legacy evidence arms remain useful inputs, but Koschei Web3 is no longer defined only by token or wallet scoring.

## Current developer routes

```text
POST /api/v1/radar/check        session-authenticated radar check
GET  /api/v1/radar/feed         authenticated verdict feed
POST /api/v1/scan/token         API-key token and batch scan
POST /api/v1/shield/preflight   API-key pre-signing risk check
POST /api/v1/shield/transaction API-key transaction simulation
GET  /api/v1/usage              API-key usage and async results
GET  /api/v1/risk/badge         public rate-limited risk badge
```

See `docs/api-reference.md` for current production behavior.

## Architecture principle

Security-critical decisions should live behind a narrow trusted boundary, preferably in deterministic services with explicit policy, evidence and auditability.

Framework choice is a presentation and integration concern, not a trust decision.

The current production architecture includes:

```text
Go API and workers
Railway deployment
Neon PostgreSQL
Solana RPC provider with automatic public fallback
Pump-style stream observations
web customer surfaces
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

- Architecture: `docs/ARCHITECTURE.md`
- Product charter: `docs/SECURITY_PRODUCT_CHARTER.md`
- Data flow: `docs/architecture/data-flow.md`
- API reference: `docs/api-reference.md`
- Developer quickstart: `docs/DEVELOPER_QUICKSTART.md`
- Signed verdict contract: `docs/signed-verdict-schema.md`
- Limitations: `docs/limitations.md`
- Technical whitepaper: `docs/technical-whitepaper.md`
- Open-source roadmap: `docs/open-source-roadmap.md`

## License

MIT — see `LICENSE`.

---

**Koschei Web3 is not a dashboard with security features. The target is a security control plane for Web3 execution, signing and infrastructure.**
