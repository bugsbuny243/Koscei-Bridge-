# KOSCHEİ WEB3 — DEFENSE VALIDATION

Koschei Web3 is an evidence-first, vendor-neutral defense-validation platform. It is being built to prove whether an exact Web3 security-control configuration catches a controlled attack before impact, reacts late, misses it or flags benign behavior.

## 30-second pitch

Koschei Web3 answers one question: **who tests the Web3 defenses?** It runs versioned attack and benign-control cases in an isolated fork/sandbox, observes the defense through an independent collector and produces a deterministic **validated, failed or incomplete** result backed by execution, state, timing and alert hashes.

It does not replace monitoring, wallets, audits or incident response. It tests whether those defenses actually work for the exact version, configuration, scenario and observation window in the report. Existing ARVIS and Defense OS capabilities become evidence and safe-execution subsystems of this product.

## Who pays — and why

| Customer | What Koschei validates | Why they pay |
| --- | --- | --- |
| Protocol and DAO security teams | Whether monitoring and response controls catch controlled exploit sequences before impact | Replace assumptions with reproducible evidence before and after a control change |
| Wallet and pre-signing teams | Whether malicious payloads are blocked without flagging matched benign activity | Measure misses, late detections and false positives against exact releases |
| Monitoring and detection vendors | Whether exact rule/configuration versions detect a versioned Web3 scenario corpus | Produce independently collected benchmark evidence instead of self-attestation |
| Audit and incident-response firms | Whether recommended controls survive realistic fork drills | Add proof-of-control to code review and post-incident remediation |
| Exchange and custody security teams | Whether privileged-access and transaction controls react within the required window | Test high-impact defenses without custody or mainnet execution |

Commercial access can be scenario packs, control adapters, isolated validation runs, continuous regression validation or enterprise evidence dossiers.

## Why Solana

Solana is the first adapter because the repository already contains the deepest safe-execution and evidence substrate there. The core evaluator is chain-independent; EVM and Tron require separate adapters and fixture corpora that preserve the same evidence contract.

The existing Solana evidence subsystem understands:

- Solana transaction instructions and account relationships
- SPL Token and Token-2022 authorities, extensions and transfer behavior
- mint and freeze authority evidence
- program-specific relations and liquidity activity
- priority-fee and pre-signing simulation context
- Pump-style launch observations
- Raydium-oriented liquidity evidence

## Current proof and next proof

Existing substrate:

- production Go API and worker pipeline
- deterministic ARVIS evidence and signed Radar verdicts
- Token-2022 scanner and transaction firewall
- immutable Defense OS artifacts, harness plans and default-off LiteSVM execution gates
- persistent watchlists, webhooks, B2B APIs and evidence dossiers

The first defense-validation slice adds a pure deterministic evaluator and fail-closed tests. It exposes no route, migration, worker action or production gate. A real product claim begins only after an owner-approved attack plus benign-control case runs through an independent collector twice with reproducible hashes.

## Technical scope

Koschei Web3's target outputs are:

1. a versioned Web3 attack and benign-control scenario corpus
2. safe fork/sandbox orchestration with no mainnet, custody or signing authority
3. vendor-neutral security-control adapters
4. independent alert and observation collection
5. exact detection time, lead time, miss and false-positive measurements
6. deterministic `VALIDATED / FAILED / INCOMPLETE` evaluation
7. immutable evidence bundles and reproducible report hashes
8. Solana-first adapters followed by separately evidenced EVM/Tron adapters

ARVIS actor intelligence, signed Radar verdicts and current developer APIs remain active evidence surfaces. They do not decide a defense-validation outcome.

## Open-source developer kit

| Component | Location | Status |
| --- | --- | --- |
| TypeScript API client | `sdk/typescript` | Shipped and tested |
| Solana event normalizer | `oss/event-normalizer` | Shipped and tested |
| Signed verdict schema | `oss/schemas/signed-verdict.schema.json` | Shipped |
| Wallet warning example | `examples/wallet-warning` | Shipped |
| Launchpad screening example | `examples/launchpad-screening` | Shipped |
| API reference | `docs/api-reference.md` | Shipped |
| Developer quickstart | `docs/DEVELOPER_QUICKSTART.md` | Shipped |
| Grant evidence matrix | `docs/grant-evidence-matrix.md` | Shipped |
| Pitch one-pager | `docs/pitch-one-pager.md` | Shipped |

The open-source packages are MIT licensed and designed to remain useful without the hosted dashboard.

## Product rule

```text
versioned attack + matched benign control
        ↓
real fork/sandbox execution
        ↓
independent observation
        ↓
deterministic validation result
```

The ARVIS evidence arms remain an internal evidence subsystem, not separate products. A defense-validation customer receives one structured result bound to the control version, configuration hash, scenario version, timing, evidence hashes and ruleset.

## Evidence policy

```text
verified execution + independent complete observation + attack/benign matrix → validation may be produced
missing, mismatched or unverified evidence                                  → INCOMPLETE
```

On-chain and off-chain observations are labeled separately. Parsed URLs are not presented as on-chain evidence. Wallet relations are not presented as real-world identity claims. A low-risk or monitor result is not a safety guarantee.

## Existing ARVIS evidence subsystem

1. Pump.fun Sybil Radar
2. Raydium Pool Guardian
3. Walletless Claim Shield
4. Intelligence Graph
5. MEV Shield
6. Token Authority Scanner
7. Holder Concentration
8. Liquidity Movement
9. Creator Link Analysis
10. Funding Cluster Detector
11. Sniper Timing Detector
12. Claim Surface Risk
13. Program Relation Scan
14. Final Verdict Engine

Each arm remains unsigned when its required evidence is unavailable.

## Existing ARVIS live pipeline

```text
Pump-style + Raydium-style observations
        ↓
transaction and account enrichment
        ↓
target normalization
        ↓
evidence-arm processing
        ↓
Final Verdict Engine
        ↓
signed risk, monitor or withheld output
```

The stream processor is idempotent. The same stream event and evidence arm cannot create duplicate final output. Processing states include healthy, processing, degraded, stale, retryable failure and exhausted failure.

## Provider resilience

ARVIS resolves one canonical Solana RPC provider at startup and applies process-wide pacing and retry controls. When the configured production provider is rate-limited or unavailable, standard Solana RPC calls automatically fall back to the public Solana mainnet endpoint.

Provider-specific limits never authorize the system to fabricate evidence. Unsupported or unavailable evidence results in a withheld or partial analysis.

## Developer routes

```text
POST /api/v1/radar/check        session-authenticated radar check
GET  /api/v1/radar/feed         authenticated verdict feed
POST /api/v1/scan/token         API-key token and batch scan
POST /api/v1/shield/preflight   API-key pre-signing risk check
POST /api/v1/shield/transaction API-key transaction simulation
GET  /api/v1/usage              API-key usage and async results
GET  /api/v1/risk/badge         public rate-limited risk badge
```

See `docs/api-reference.md` for authentication boundaries and current production status.

## Integration pilot

The first defense-validation pilot is for a team with one exact security control and explicit authorization to test it in an isolated Solana environment.

A strong pilot has:

- one named security owner and written test scope
- one pinned control version and configuration hash
- one attack case plus a matched benign control
- one independently observed detection deadline
- no mainnet, custody, signing or automatic-intervention requirement
- permission to publish anonymized technical benchmark evidence

Apply through the production `/pilot` page.

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

## Production architecture

```text
Go API and workers
Railway deployment
Neon PostgreSQL
Solana RPC provider with automatic public fallback
Pump-style stream observations
Vanilla HTML / CSS / JavaScript customer surfaces
```

Secrets and production credentials live only in the deployment environment and are not committed to the repository.

## Access model

Paid analysis is entitlement-backed. A profile label alone cannot unlock premium output.

```text
active entitlement + remaining output → analysis allowed
failed evidence collection             → no output charged
successful evidence-backed analysis    → one output consumed
```

## Documentation

- Defense validation contract: `WEB3_DEFENSE_VALIDATION_ENGINE.md`
- Actor investigation subsystem: `ACTOR_INVESTIGATION_ENGINE.md`
- Architecture: `docs/ARCHITECTURE.md`
- Data flow: `docs/architecture/data-flow.md`
- API reference: `docs/api-reference.md`
- Developer quickstart: `docs/DEVELOPER_QUICKSTART.md`
- Signed verdict contract: `docs/signed-verdict-schema.md`
- Limitations: `docs/limitations.md`
- Technical whitepaper: `docs/technical-whitepaper.md`
- Open-source roadmap: `docs/open-source-roadmap.md`
- Pitch one-pager: `docs/pitch-one-pager.md`
- Grant resubmission: `docs/grant-v3-proposal.md`
- Grant evidence matrix: `docs/grant-evidence-matrix.md`

## License

MIT — see `LICENSE`.

---

Building the evidence layer that tests whether Web3 defenses actually work. Solana first; vendor-neutral and chain-adapter based.
