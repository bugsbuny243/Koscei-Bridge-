# KOSCH Security Layer v1

Status: active security boundary  
Scope: Koschei Web3 Hub KOSCH access and future ecosystem integration  
Actor Investigation Engine references: sections 3, 4, 5 and 6  
Actor ruleset: v1.0  
Unified Radar authority: deterministic rules only

## Purpose

KOSCH is embedded into Koschei as a cryptographically verifiable access and security-coordination primitive. It is not a source of truth about whether a wallet, token, model, compiler build, transaction, package or user is safe.

The invariant is:

> KOSCH can unlock bounded access, capacity and contribution workflows. KOSCH can never buy technical authority.

The official mint is:

```text
HHPpU9u56Bwxov12nf7DXUCuv6h1q5j1xgGS3yukpump
```

## Current runtime boundary

The current Web3 path is:

```text
verified user identity
        ↓
verified Solana wallet link
        ↓
confirmed KOSCH balance snapshot
        ↓
KOSCH tier
        ↓
named capability allowlist
        ↓
bounded product access
```

The token gate fails closed when wallet proof, mint configuration, RPC verification or balance evidence is unavailable.

## Named access capabilities

### Basic

- `identity.proof`
- `security.scan.basic`
- `security.contribution.submit`

### Pro

Basic plus:

- `security.radar.advanced`
- `security.exposure.report`
- `intelligence.actor_graph`
- `security.watchlist`

### Enterprise

Pro plus:

- `intelligence.evidence_export`
- `developer.webhooks`
- `developer.api`
- `developer.deterministic_agents`

These names represent product access only. They are not operating-system, compiler, model or verdict capabilities.

## Powers KOSCH must never grant

The following authority classes are forbidden regardless of holdings, tier, stake, account status or future price:

```text
evidence.write
evidence.mutate
verdict.override
verdict.lower_risk
verdict.publish_bypass
capability.grant
capability.expand
compiler.bypass
compiler.policy_override
sentinel.promote
sentinel.deploy
sentinel.verdict_authority
integration.approve
```

This deny set is represented in code and covered by tests. Future tiers may add access/capacity capabilities, but they must not add any authority from this class.

## Evidence and verdict isolation

KOSCH state is not evidence in an Actor Investigation Engine case. Holder status cannot:

- change `VERIFIED / OBSERVED / INFERRED / UNVERIFIED` classification;
- add or remove evidence rows;
- alter a bundle digest or signature;
- trigger, suppress, raise or lower a deterministic rule;
- change the final letter verdict;
- bypass an unavailable/withheld result;
- influence publication eligibility.

KOSCH may control whether a user is allowed to request a deeper bounded query, but the answer to that query remains determined exclusively by the evidence and rules.

## Future Koschei Language integration

When the Koschei language passes its independent maturity gates, KOSCH proof may be represented as an application-level capability input. The language/compiler must still enforce this rule:

```text
KOSCH proof -> may authorize a declared product operation
KOSCH proof -> may NOT create ambient authority
KOSCH proof -> may NOT widen an existing capability
KOSCH proof -> may NOT bypass compiler/runtime policy
```

The token therefore participates inside the capability system without becoming a root capability.

## Future Sentinel integration

When Sentinel passes its independent promotion and runtime-integration gates, KOSCH may participate in authenticated access, rate control, contribution/bounty identity and bounded resource allocation.

KOSCH must never:

- change a model prediction into evidence;
- raise model confidence;
- suppress model abstention;
- promote a candidate;
- select a weaker safety policy;
- grant the model new runtime authority.

Sentinel remains subordinate to deterministic security policy even when KOSCH is present.

## Contribution and bounty direction

A future security contribution workflow may use KOSCH for economic coordination:

```text
submission
   ↓
quarantine
   ↓
reproduction / deterministic verification
   ↓
provenance and evidence checks
   ↓
accepted security contribution
   ↓
optional KOSCH reward
```

Reward follows verification. Stake, holdings or payment never make a claim true.

## Acceptance invariants

A release touching KOSCH access passes this security contract only if all statements remain true:

1. No KOSCH tier can mutate evidence.
2. No KOSCH tier can override a verdict.
3. No KOSCH tier can widen compiler/runtime authority.
4. No KOSCH tier can promote or deploy Sentinel.
5. No KOSCH tier can approve ecosystem integration.
6. Wallet and token proof fail closed when verification is unavailable.
7. Product access is expressed through named allowlisted capabilities.
8. Capability lists returned to callers are copies, not mutable canonical policy state.
9. The official mint identity never implies safety.
10. Financial value, price or holdings never influence technical truth.

## Current implementation

The v1 boundary is implemented in:

```text
koschei/api/internal/handlers/kosch_security_policy.go
koschei/api/internal/handlers/kosch_security_policy_test.go
koschei/api/internal/handlers/api_key_kosch_access.go
koschei/api/internal/handlers/entitlement.go
koschei/api/internal/handlers/owner_kosch_access_v2.go
```

This is the foundation layer. It deliberately does not connect KOSCH to Sentinel verdict authority or Koschei compiler bypasses; those powers are forbidden rather than merely disabled.
