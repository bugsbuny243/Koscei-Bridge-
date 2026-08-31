# Koschei Product Boundary Contract

Status: canonical architecture contract  
Current product focus: `web3_only`  
Scope: Koschei Web3 Hub / ARVIS

## 1. Active product

Koschei Web3 Hub / ARVIS is the active production product. It owns Web3 security validation, evidence collection, durable security memory, deterministic rules, customer decision support, and signed verdicts.

Koschei Sentinel is cancelled and is not an active product, dependency, integration target, roadmap layer, or runtime authority.

Koschei Lang remains a separate early-stage project. It is not ready for production Web3 integration and must not become a build, deployment, runtime, migration, worker, incident-recovery, authorization, or verdict dependency of Koschei Web3.

## 2. Production isolation

Production Web3 Hub must not:

- call Sentinel or depend on Sentinel artifacts;
- present Sentinel as a current or future required Web3 layer;
- import, compile, or execute Koschei Lang code in the production request path;
- require the Koschei compiler or runtime for deployment, migrations, workers, billing, authentication, or incident recovery;
- present Koschei Lang as already integrated into the live product;
- derive customer access from transferable assets, token holdings, wallet balances, or holder tiers.

Paid product access is controlled by active SaaS entitlements. Payment providers are external collection paths only and never become customer authorization or verdict authorities.

## 3. Provider policy

Helius, canonical Solana RPC, and protocol-specific sources are evidence transports, not verdict authorities.

```text
provider observations
        ↓
Koschei normalization
        ↓
evidence verification
        ↓
durable ARVIS memory
        ↓
deterministic decision logic
        ↓
signed / auditable output
```

Missing provider data must remain unavailable or UNKNOWN. It must never be converted into SAFE merely because a source did not return evidence.

## 4. Native intelligence that Web3 Hub must own

### Cross-token actor graph

Connect verified on-chain roles and relations across launches without claiming real-world identity. Every relation must preserve provenance, observed time, verification state, and evidence references.

### Repeat harmful-operator corpus

Preserve versioned evidence for actors or clusters that repeatedly exhibit verified harmful launch, authority, liquidity, or exit behavior. Funding or selling activity alone is not sufficient for adverse classification.

### Verdict history and evidence bundles

A new verdict never rewrites an old signed verdict. Evidence bundles and verdict revisions remain auditable and immutable after publication.

### Funding-cluster history

Direct transfers and inferred co-occurrence remain distinct. Inferred cluster membership is intelligence for review and cannot independently create a fraud verdict.

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

Raw provider payloads are source material, not permanent truth by themselves.

## 6. Koschei Lang boundary

Koschei Lang is intentionally deferred. Until a separate future decision explicitly reopens integration work, Web3 Hub may only treat it as an external research project.

No Web3 production component may be implemented in Koschei Lang until the language has independently proven stable syntax, type and capability semantics, reproducible builds, runtime/ABI stability, fuzzing and adversarial validation, interoperability, and a reversible reference implementation with equivalent external behavior.

Even after those conditions exist, any Web3 integration requires a separate owner-approved project. There is no automatic integration roadmap.

## 7. Current implementation sequence

1. Keep Koschei Web3 / ARVIS production-independent.
2. Improve Web3 product usefulness, evidence quality, resilience, and operator value.
3. Preserve Helius and existing Solana collection behind provider boundaries.
4. Expand durable actor, incident, funding, and verdict memory where it improves customer decisions.
5. Ship bounded intelligence and pre-sign security capabilities without inventing evidence or unfinished production claims.
6. Keep commercial access SaaS-entitlement based and independent from blockchain assets.

## 8. Acceptance rule

```text
Koschei Web3 = active standalone product
Koschei Sentinel = cancelled
Koschei Lang = separate and deferred
```

No current Web3 work should be framed as a phased Web3–Sentinel–Lang integration program.
