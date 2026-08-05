# Koschei Ecosystem Contract v1

Status: canonical architecture contract  
Scope: Koschei Web3 Hub, Koschei language, Koschei Sentinel and the official KOSCH Solana asset

## 1. One ecosystem, four independent responsibilities

| Component | Canonical responsibility | Must never own |
| --- | --- | --- |
| Koschei Web3 Hub / ARVIS | Solana evidence collection, durable security memory, deterministic rules and signed verdicts | Compiler semantics, model training authority or token price support |
| Koschei language | A new capability-secure programming language with explicit authority and broad interoperability | ARVIS production verdicts, holder entitlements or model-generated security claims |
| Koschei Sentinel | A Solana-security model trained on privacy-safe, evidence-grounded ARVIS data | Final verdict authority, evidence fabrication or autonomous production execution |
| KOSCH asset | Verifiable ecosystem identity, access and contribution coordination | Buying a safer verdict, changing compiler behavior, changing evidence or promising financial return |

Repositories:

- Web3 Hub: `https://github.com/bugsbuny243/Koschei-Web3-Hub`
- Language: `https://github.com/bugsbuny243/koschei-lang`
- Sentinel: `https://github.com/bugsbuny243/koschei-sentinel`

Official KOSCH mint:

```text
HHPpU9u56Bwxov12nf7DXUCuv6h1q5j1xgGS3yukpump
```

Pump callout:

```text
https://pump.fun/callouts/HHPpU9u56Bwxov12nf7DXUCuv6h1q5j1xgGS3yukpump/62c9a163-75a7-4f45-914c-1c9479d3a5ec
```

The mint identifies the ecosystem asset. It is not evidence that a user, token, wallet or transaction is safe.

## 2. Provider policy: keep Helius, own the missing intelligence

Helius remains a supported Solana data and delivery provider. Existing Helius-backed RPC, parsed transaction, webhook and enrichment paths must not be broken merely to replace the provider.

ARVIS owns every query that requires durable cross-token memory, historical attribution or Koschei-specific evidence semantics.

```text
Helius / canonical Solana RPC / protocol-specific sources
                       ↓
raw observations, parsed transactions and account state
                       ↓
Koschei normalization and evidence verification
                       ↓
Koschei durable actor, incident, funding and verdict memory
                       ↓
deterministic ARVIS queries and signed verdicts
```

Provider output is source material, not a verdict. A provider outage, unsupported parser or missing field must produce unavailable or withheld evidence rather than an invented relation.

## 3. Native intelligence that Koschei must own

### 3.1 Cross-token actor identity graph

Purpose: connect verified on-chain roles and relations across many token launches without claiming real-world identity.

Canonical node kinds:

- token mint
- wallet
- token account
- program
- liquidity pool
- funding cluster
- incident family
- signed verdict revision

Canonical edge kinds include:

- created or deployed
- funded
- received creator outflow
- controlled token balance
- co-funded
- co-launched
- co-fired in an early-buyer window
- removed or added liquidity
- invoked program
- linked by a specific evidence bundle

Every edge must carry provenance, observed time, verification state and evidence references. Wallet relations are on-chain actor relations, not claims about a natural person's identity.

### 3.2 Repeat rug-operator corpus

Purpose: preserve the historical record of actors and incident families that repeatedly exhibit verified harmful launch, authority, liquidity or exit behavior.

A wallet or cluster is not added merely because it funded many launches or sold a token. Corpus membership requires versioned deterministic criteria and one or more verified incident bundles.

Required properties:

- immutable incident-family identifier
- member actor references
- affected token mints
- first and last verified observation
- behavior taxonomy and ruleset version
- supporting signatures, slots and evidence IDs
- confidence ceiling derived from the weakest material evidence
- supersession history when a later ruleset changes interpretation

### 3.3 Verdict history and evidence bundles

Purpose: answer what ARVIS knew, when it knew it and which rules produced each decision.

A new verdict never rewrites an old signed verdict. The system stores a revision chain:

```text
target + ruleset + evidence snapshot
              ↓
immutable evidence bundle
              ↓
signed verdict revision
              ↓
current / historical / superseded presentation state
```

Historical results remain auditable. Public presentation must clearly label superseded revisions and link to the current revision without changing the old bundle hash.

### 3.4 Funding-cluster history

Purpose: answer which funding cluster previously funded which creators, launches, wallets and incident families.

The cluster memory must support at least these evidence-bounded questions:

- Which token launches received initial or material funding from this cluster?
- Which creators were funded by the same source actors?
- Which funded launches later received verified high-risk or incident verdicts?
- Did the cluster reappear after a dormancy window?
- Which relations are direct transfers and which are inferred co-occurrence?
- What is the earliest and latest verified activity for the cluster?

Direct transfer evidence and inferred clustering must remain separate. Inferred cluster membership is watch intelligence and cannot independently create a fraud grade.

## 4. Minimum durable data contract

The physical schema may evolve, but the logical contract must preserve these records:

| Logical record | Required identity |
| --- | --- |
| actor entity | stable pseudonymous actor reference + chain + entity kind |
| actor relation | source + destination + relation kind + evidence bundle + observed time |
| funding cluster | cluster reference + version + member evidence + lifecycle timestamps |
| incident family | family reference + taxonomy + ruleset + supporting bundles |
| evidence bundle | immutable digest + evidence rows + source snapshots + limitations |
| verdict revision | target + ruleset + bundle digest + signature + generated time + status |
| provider observation | provider + request class + source timestamp + normalized digest |

Raw provider payloads must not become permanent truth merely because they were received. Long-lived memory stores normalized facts, provenance and digests under explicit retention rules.

## 5. Native query families

ARVIS should expose owner/research APIs first, then bounded customer APIs after privacy, abuse and cost controls pass.

Planned query families:

```text
GET /api/owner/intelligence/actor-graph?target=<mint-or-wallet>
GET /api/owner/intelligence/repeat-operators?actor=<actor-ref>
GET /api/owner/intelligence/funding-history?cluster=<cluster-ref>
GET /api/owner/intelligence/verdict-history?target=<mint>
GET /api/owner/intelligence/evidence-bundles?target=<mint>
```

Customer routes must return masked or pseudonymous references when raw addresses are not needed. Bulk graph traversal must be bounded by depth, node count, time range and entitlement.

## 6. Deterministic ARVIS and Sentinel boundary

ARVIS owns:

- source collection and normalization
- evidence verification
- actor and incident memory
- deterministic rule execution
- final grade, action and signature

Sentinel may:

- explain the evidence bundle
- summarize prior related incidents
- surface missing evidence and limitations
- rank investigation leads without changing the verdict
- generate structured analyst commentary with cited evidence IDs

Sentinel may not:

- modify immutable verdict fields
- invent a wallet relation
- exceed evidence confidence
- promote inferred evidence into verified evidence
- sign or publish a final ARVIS verdict

## 7. Koschei language boundary

The language is a standalone capability-secure programming language. Web3 Hub may become a demanding reference application and interoperability customer, but the compiler must not become a token-gated or Solana-only product.

The security target is measured improvement, not an unsupported slogan. Claims such as being safer than Rust require reproducible benchmarks covering authority containment, supply-chain reach, memory and concurrency safety, backend parity and escape resistance.

Interoperability must be explicit and bounded through stable interfaces such as generated C/Go ABI adapters, JSON/HTTP, process capabilities, package manifests and future WASM or native foreign-function contracts. Compatibility must not reintroduce ambient authority.

## 8. KOSCH utility contract

Permitted ecosystem uses include:

- proving possession of the official ecosystem asset
- unlocking explicitly documented premium depth or capacity
- receiving transparent usage credits or contribution recognition
- voting or signaling on non-security product priorities after a separate governance design is approved
- accessing community programs, bounties or ecosystem events

Forbidden coupling:

- holdings cannot lower a risk grade or bypass a withheld verdict
- holdings cannot alter evidence, bundle hashes or signatures
- holdings cannot disable compiler checks or capability rules
- holdings cannot promote a Sentinel candidate
- holdings cannot guarantee profit, price support, yield or investment safety
- token payments never authorize wallet custody, signing or transaction submission

Public basic security checks remain available under the existing free-core policy. Token utility must be documented as product access and coordination, not as a promise of financial return.

## 9. Implementation sequence

### Phase A — preserve and formalize

1. Keep current Helius/RPC paths working.
2. Publish this ecosystem and provider-boundary contract.
3. Publish the exact official mint and asset-identity disclaimer.
4. Inventory existing actor graph, repeat actor, funding cluster, verdict history and evidence-bundle paths.

### Phase B — durable native memory

1. Complete stable actor references and evidence-linked relations.
2. Persist funding-cluster lifecycle and historical launch links.
3. Persist repeat-operator incident families under deterministic criteria.
4. Preserve immutable verdict revision chains and superseded presentation state.
5. Add retention and archive rules that preserve audit-critical bundles.

### Phase C — native queries

1. Ship owner/research endpoints with bounded traversal.
2. Add deterministic query tests and replay fixtures.
3. Add masked customer outputs only after privacy and abuse review.
4. Measure provider dependency, query latency, coverage and withheld rates.

### Phase D — Sentinel and language integration

1. Export privacy-safe graph, incident, funding and verdict examples to Sentinel.
2. Prevent family or cluster leakage across train/validation/test splits.
3. Use Web3 Hub as a reference application for Koschei interoperability only after the language interfaces are real and tested.
4. Keep the final ARVIS verdict deterministic through every integration.

## 10. Acceptance rule

The ecosystem is integrated only when all four components can be used together without violating their authority boundaries:

```text
provider data can fail without fabricated evidence
ARVIS history can evolve without rewriting old truth
Sentinel can explain without becoming the judge
KOSCH can unlock utility without buying security truth
Koschei language can interoperate without surrendering capability safety
```
