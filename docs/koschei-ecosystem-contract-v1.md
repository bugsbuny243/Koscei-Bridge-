# Koschei Ecosystem Contract v1

Status: canonical architecture contract  
Integration state: `incubation_only`  
Scope: Koschei Web3 Hub, Koschei language, Koschei Sentinel and the official KOSCH Solana asset

## 1. One ecosystem, independent products

The projects share an ecosystem identity and long-term direction, but they are not one runtime system today.

| Component | Current responsibility | Current integration state | Must never own |
| --- | --- | --- | --- |
| Koschei Web3 Hub / ARVIS | Solana evidence collection, durable security memory, deterministic rules and signed verdicts | production-independent | Compiler semantics, model promotion authority or token price support |
| Koschei language | Independent capability-secure language research, compiler/runtime development and interoperability tests | incubation-only | ARVIS production verdicts, Web3 runtime dependencies or token-controlled compiler behavior |
| Koschei Sentinel | Offline Solana-security dataset, training, evaluation and model-lineage research | incubation-only | Final verdict authority, evidence fabrication, Web3 runtime execution or automatic production deployment |
| KOSCH asset | Verifiable ecosystem identity and separately documented access/community coordination | identity/utility only | Buying a safer verdict, changing compiler behavior, changing model promotion or promising financial return |

Repositories:

- Web3 Hub: `https://github.com/bugsbuny243/Koschei-Web3-Hub`
- Language: `https://github.com/bugsbuny243/koschei-lang`
- Sentinel: `https://github.com/bugsbuny243/koschei-sentinel`

Official KOSCH mint:

```text
HHPpU9u56Bwxov12nf7DXUCuv6h1q5j1xgGS3yukpump
```

The mint identifies the ecosystem asset. It is not evidence that a user, token, wallet, model, compiler build or transaction is safe.

## 2. Incubation firewall

Until separately approved maturity gates pass, production Web3 Hub must not:

- call Sentinel during a customer request;
- use Sentinel output in a verdict, grade, publication or blocking decision;
- depend on Sentinel availability to start or remain healthy;
- import, compile or execute Koschei language code in the production request path;
- require the Koschei compiler or runtime for deployment, migrations, workers or incident recovery;
- present either project as already integrated into the live product.

Allowed during incubation:

- read-only, privacy-safe offline dataset extraction from ARVIS to Sentinel;
- historical replay, shadow evaluation and benchmark generation outside the customer path;
- Web3-derived compiler fixtures, examples and interoperability prototypes outside production;
- documentation links, shared ecosystem identity and independently governed contribution programs;
- reversible experiments on isolated branches and non-production environments.

The distinction is permanent until an explicit future decision changes it:

```text
shared data and benchmarks  !=  runtime integration
shared ecosystem identity   !=  shared production authority
```

## 3. Provider policy: keep Helius, own the missing intelligence

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

## 4. Native intelligence that Web3 Hub must own

### 4.1 Cross-token actor graph

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

Every edge must carry provenance, observed time, verification state and evidence references. Wallet relations are on-chain actor relations, not claims about a natural person's identity.

### 4.2 Repeat rug-operator corpus

Purpose: preserve the historical record of actors and incident families that repeatedly exhibit verified harmful launch, authority, liquidity or exit behavior.

A wallet or cluster is not added merely because it funded many launches or sold a token. Corpus membership requires versioned deterministic criteria and one or more verified incident bundles.

### 4.3 Verdict history and evidence bundles

A new verdict never rewrites an old signed verdict. The system preserves:

```text
target + ruleset + evidence snapshot
              ↓
immutable evidence bundle
              ↓
signed verdict revision
              ↓
current / historical / superseded presentation state
```

Historical results remain auditable. A newer verdict may supersede an older presentation, but it cannot alter the old bundle hash or signature.

### 4.4 Funding-cluster history

The cluster memory must answer evidence-bounded questions about prior launches, creators, direct funding transfers, reappearance and later verified incidents. Direct transfers and inferred co-occurrence remain separate. Inferred cluster membership is watch intelligence and cannot independently create a fraud grade.

## 5. Minimum durable data contract

| Logical record | Required identity |
| --- | --- |
| actor entity | stable actor reference + chain + entity kind |
| actor relation | source + destination + relation kind + evidence bundle + observed time |
| funding cluster | cluster reference + version + member evidence + lifecycle timestamps |
| incident family | family reference + taxonomy + ruleset + supporting bundles |
| evidence bundle | immutable digest + evidence rows + source snapshots + limitations |
| verdict revision | target + ruleset + bundle digest + signature + generated time + status |
| provider observation | provider + request class + source timestamp + normalized digest |

Raw provider payloads must not become permanent truth merely because they were received. Long-lived memory stores normalized facts, provenance and digests under explicit retention rules.

## 6. Native query families

Owner/research routes come first. Customer exposure follows only after privacy, abuse and cost review.

```text
GET /api/owner/intelligence/actor-graph?target=<mint-or-wallet>
GET /api/owner/intelligence/repeat-operators?actor=<actor-ref>
GET /api/owner/intelligence/funding-history?cluster=<cluster-ref>
GET /api/owner/intelligence/verdict-history?target=<mint>
GET /api/owner/intelligence/evidence-bundles?target=<mint>
```

Bulk graph traversal must be bounded by depth, node count, time range and entitlement.

## 7. Sentinel boundary during incubation

ARVIS owns facts, evidence verification, deterministic rules, final grade, final action and signatures.

Sentinel may currently operate only offline or in isolated research environments to:

- train on privacy-safe snapshots;
- replay historical evidence bundles;
- compare model candidates;
- test evidence citation, limitations and abstention;
- generate non-production analyst commentary for evaluation.

Sentinel must not currently:

- receive live customer requests from Web3 Hub;
- appear in the production verdict path;
- publish customer-facing commentary;
- write to ARVIS evidence or verdict tables;
- alter immutable verdict fields;
- promote itself or deploy automatically;
- become a production startup dependency.

## 8. Koschei language boundary during incubation

The language remains a standalone project. Web3 Hub may supply difficult fixtures and benchmark cases, but production Web3 components remain in their existing implementation until the language is mature and separately approved.

During incubation the language may:

- model bounded evidence-processing examples;
- generate experimental adapters;
- use Web3 cases in compiler, capability and interoperability tests;
- measure security ceremony against existing implementations.

It must not currently:

- replace production Go/JavaScript components;
- become a build or deployment dependency;
- run in production workers;
- be required for incident recovery;
- be advertised as securing the live Web3 system.

## 9. Future Sentinel integration gates

No Sentinel runtime integration proposal may begin until all gates have documented evidence:

1. dataset lineage, privacy and family-safe splitting pass;
2. multiple consecutive candidate releases pass every hard authority, grounding, abstention and privacy gate;
3. historical replay shows no invented evidence, changed verdict or unsupported certainty;
4. prompt-injection and data-poisoning suites pass;
5. latency, cost, availability, rollback and model-version observability are proven;
6. Sentinel remains optional and fail-closed behind deterministic ARVIS output;
7. an owner-approved integration decision explicitly authorizes the next stage.

Even after approval, rollout order is historical replay, shadow-only traffic, owner-only review, bounded canary and only then optional production commentary. No model receives verdict authority.

## 10. Future language integration gates

No Web3 production component may be implemented in Koschei until all relevant gates pass:

1. stable syntax, type-system and capability semantics;
2. frozen runtime/ABI contract for the required boundary;
3. package integrity, lock files and reproducible builds;
4. interpreter/native/foreign-adapter parity;
5. fuzzing, adversarial capability tests and cross-platform validation;
6. measurable security and ergonomics benchmarks;
7. a reversible reference component with equivalent external behavior;
8. an owner-approved integration decision explicitly authorizes the component.

A future integration begins with a small replaceable component, never a production rewrite.

## 11. KOSCH utility contract

Permitted uses may include documented access, capacity, contribution recognition, community programs or bounties. Forbidden coupling remains absolute:

- holdings cannot lower a risk grade or bypass a withheld verdict;
- holdings cannot alter evidence, bundle hashes or signatures;
- holdings cannot disable compiler checks or capability rules;
- holdings cannot promote or deploy a Sentinel candidate;
- holdings cannot authorize a premature Web3 integration;
- holdings cannot guarantee profit, price support, yield or investment safety.

## 12. Current implementation sequence

### Active Web3 work

1. Preserve Helius and existing Solana collection.
2. Complete durable actor, incident, funding and verdict memory.
3. Ship bounded native intelligence queries.
4. Improve production evidence quality, resilience and auditability.

### Background Sentinel work

1. Build privacy-safe historical datasets.
2. Train and evaluate model candidates offline.
3. Preserve full lineage, benchmark and rejection records.
4. Do not connect the candidate to production Web3.

### Background language work

1. Continue compiler, runtime, capability and interoperability development.
2. Build independent benchmarks and real standalone programs.
3. Use Web3 only as an offline stress-test source.
4. Do not replace or couple production Web3 code.

## 13. Acceptance rule

The ecosystem may share identity while runtime integration remains disabled.

```text
Web3 Hub remains production-independent
Sentinel matures offline without customer authority
Koschei language matures independently without production dependency
KOSCH coordinates utility without changing technical truth
```

A future integration is a separate reviewed project, not an automatic consequence of belonging to the same ecosystem.
