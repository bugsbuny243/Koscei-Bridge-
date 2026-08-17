# Koschei Web3 Security Product Charter

## Purpose

Koschei Web3 exists to close practical Web3 security gaps between **what developers intend**, **what users or operators sign**, **what infrastructure relays**, and **what ultimately executes on-chain**.

The project should be judged by whether it can prevent or materially reduce real security failures, not by the number of dashboards, scores or supported chains it can display.

## Primary objective

Build a Web3 security control plane capable of producing independent, evidence-backed security decisions before irreversible execution.

The platform should progressively cover:

1. execution integrity
2. signing defense
3. infrastructure and node defense
4. privileged-operation monitoring
5. cross-chain security evidence
6. automated containment where safe and explicitly authorized

## Product principles

### Evidence before confidence

No verified evidence means no fabricated certainty. Missing evidence must be represented as missing, partial or withheld.

### Independent verification

Security-critical claims should not rely solely on the same UI, machine, RPC path or build path that generated the action being verified.

### Narrow authority

Every component should receive the minimum authority required for its job. Presentation layers must not inherit security authority by convenience.

### Deterministic decisions where possible

Canonicalization, payload comparison, policy evaluation and evidence records should be deterministic wherever the underlying protocol allows it.

### Chain-specific semantics

Multi-chain support must not flatten different execution models into one generic score. Each chain adapter must preserve the security semantics of that chain.

### Fail explicit

Unsupported, degraded or contradictory evidence should produce explicit states, not silent success.

## Product boundaries

### Koschei Web3 owns

- Web3 product integrations
- security control-plane APIs
- execution verification
- signing defense
- evidence orchestration
- chain adapters
- infrastructure security controls
- operator-facing security workflows

### Koschei Sentinel owns

- security intelligence
- adversarial reasoning
- detection and correlation
- attack-pattern learning
- ecosystem-wide security analysis

### Koschei Lang owns

- secure language/runtime design
- hardened execution primitives
- authority and capability primitives
- high-assurance software construction mechanisms

The three projects may integrate, but their responsibilities remain separate.

## Current proving ground

The existing Solana-native ARVIS system remains the current operational proving ground. Its transaction firewall, token evidence, radar, signed verdicts, API surface and monitoring pipeline are retained as real deployed capability.

Future work should use this foundation to validate stronger security controls rather than replacing working infrastructure for cosmetic architectural reasons.

## Near-term build sequence

### Phase 1 — Execution Proof

Prove intended payload versus executable payload before signature or privileged execution.

Deliverables should center on canonical reconstruction, byte/instruction comparison, simulation, policy evaluation and auditable mismatch evidence.

### Phase 2 — Signing Defense

Move verification closer to the signer and make compromised presentation paths less able to alter meaning unnoticed.

### Phase 3 — Infrastructure Defense

Add independent evidence for RPC, node, deployment, bridge and privileged-operation paths.

### Phase 4 — Multi-chain security adapters

Expand only when each new chain can preserve its own trust and execution semantics.

### Phase 5 — Sentinel integration

Use Sentinel for higher-order correlation, attack reasoning and ecosystem intelligence without making model output the sole source of authority for deterministic security decisions.

### Phase 6 — Koschei Lang integration

Adopt hardened Koschei Lang/runtime primitives when they are mature enough to materially improve execution integrity or authority isolation.

## Non-goals

Koschei Web3 should not become:

- a generic token-score website
- a dashboard-first product
- a Solana-only branding exercise
- a frontend framework project
- an AI wrapper that replaces deterministic verification
- a collection of unrelated security features without a common trust model

## Success criteria

A capability belongs in Koschei Web3 when it can answer at least one of these questions with stronger evidence than the system being protected:

- Is this the exact action the signer intended?
- Can this payload be independently reconstructed?
- Has anything changed between review, approval and execution?
- Is this authority permitted by policy?
- Is the infrastructure path behaving consistently and safely?
- Can the system produce auditable evidence for why it allowed, warned, blocked or withheld?

The long-term target is not "more Web3 analytics." It is **stronger control over dangerous Web3 execution paths**.
