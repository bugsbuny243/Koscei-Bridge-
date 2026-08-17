# Architecture Overview

Koschei Web3 is evolving from a Solana-native risk-intelligence service into a broader **Web3 security control plane**. The current Solana implementation remains the production proving ground; broader chain and infrastructure support must preserve chain-specific trust semantics.

## Trust model

The central architectural rule is simple:

> Presentation is untrusted. Security authority lives in narrowly scoped trusted services.

A browser, Next.js application, mobile app, wallet extension or CLI may request analysis and render evidence, but it must not define the final security decision or hold security-critical authority merely because it owns the user interface.

```text
Web / Next.js / mobile / wallet / CLI
                 │
                 │ untrusted request + presentation
                 ▼
        Koschei Web3 control plane
                 │
     ┌───────────┼────────────┐
     ▼           ▼            ▼
 evidence   execution     policy / decision
 collection verification      engine
     │           │            │
     └───────────┼────────────┘
                 ▼
      allow / warn / block / withhold
                 │
                 ▼
       signed / auditable evidence
```

## Security planes

### 1. Evidence plane

Collect supported on-chain and off-chain evidence while preserving provenance and source boundaries.

A URL-derived claim is not represented as on-chain proof. A program relation is not represented as confirmed wallet coordination without the required graph evidence. Unsupported evidence remains unsupported.

### 2. Execution-integrity plane

Independently reconstruct and verify the artifact that will actually execute.

The target boundary includes transaction instructions, calldata, serialized payloads, deployment artifacts and other execution inputs where byte-level integrity matters.

Important properties:

- deterministic canonicalization where the chain or protocol permits it
- comparison of intended and executable payloads
- simulation against relevant state
- mutation detection
- explicit mismatch failure
- auditable evidence output

### 3. Signing-defense plane

Separate human intent from the potentially compromised surface presenting a signature request.

The trusted service should be able to answer:

- What is the signer being asked to authorize?
- What bytes or instructions will actually execute?
- Was the payload reconstructed independently?
- Does policy permit this authority and effect?
- Did the payload change between verification and signature?

### 4. Infrastructure-defense plane

Extend security evidence beyond contracts and tokens into the operational path that can alter execution.

Target domains include:

- RPC integrity and provider divergence
- node / validator health and hostile-state signals
- deployment authorization
- privileged protocol operations
- bridge operations
- supply-chain evidence
- operator and CI/CD execution paths

### 5. Decision plane

Produce machine-readable `allow`, `warn`, `block` or `withhold` outcomes only when the evidence boundary permits them.

Missing evidence does not silently become a low-risk result.

## Current Solana production flow

The existing production path remains:

```text
Solana RPC and supported program activity
        ↓
transaction and account parsing
        ↓
target resolution
        ↓
evidence normalization
        ↓
ARVIS analysis arms
        ↓
Final Verdict Engine
        ↓
API, dashboard, radar and report surfaces
```

This remains useful production capability and provides the foundation for the broader security control plane.

## Frontend boundary

Framework choice is explicitly outside the trusted security core.

Next.js may be used for a customer or operator interface. Vanilla JavaScript, another framework or a native client may also be used. None of these choices may become authoritative for security merely because they sit closest to the user.

The frontend must not be the sole authority for:

- canonical payload construction
- final allow / block decisions
- signer private keys
- policy grants
- privileged deployment authorization
- bridge or validator authority
- Sentinel security decisions

Security-sensitive state must be independently verified by trusted backend/runtime components.

## Project boundaries

### Koschei Web3

Product and security-control-plane layer. Owns integration surfaces, evidence orchestration, execution/signing defense and Web3 infrastructure security capabilities.

### Koschei Sentinel

Separate project intended to become the security-intelligence brain: detection, reasoning, correlation, adversarial analysis and ecosystem-wide security intelligence.

### Koschei Lang

Separate project intended to provide hardened language/runtime primitives for high-security software, authority control and execution integrity.

Koschei Web3 may consume capabilities from Sentinel or Koschei Lang in the future, but it must not collapse their repositories or responsibilities into one codebase.

## Reliability properties

The current stream processor is designed to be idempotent: the same stream event and analysis arm must not create duplicate verdicts.

Pipeline health states include:

- `healthy`
- `processing`
- `degraded`
- `stale`
- `waiting_for_stream`
- `waiting_for_enriched_targets`
- `waiting_for_processing`

Future security planes should follow the same philosophy: deterministic inputs where possible, explicit degraded states, no fabricated evidence, and auditability across decision boundaries.

## Data layer

Neon Postgres stores radar events, processing jobs, verdicts, recovery state and idempotency constraints. Database migrations are the source of truth for schema evolution.

Security-critical evidence should remain attributable to its source and decision version so that a later operator can determine why a decision was made.

## Runtime boundary

The production deployment environment supplies credentials and provider configuration. Secrets are not committed to the repository.

A deployment environment is not automatically trusted simply because it is production. Privileged operations should be minimized, policy-bound and independently auditable.

## External integration boundary

The public integration layer should expose stable, versioned schemas while keeping proprietary verdict logic and internal heuristics behind the service boundary.

Open-source components should focus on reusable ecosystem primitives such as decoding, schema helpers, evidence formats, examples and integration starters.
