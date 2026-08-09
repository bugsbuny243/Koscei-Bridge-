# Koschei Exit Impact v2

Status: evidence-layer foundation; informational only and not wired into security scoring or final verdicts.

## Goal

Exit Liquidity already asks Jupiter for read-only ExactIn quotes at fixed USD notionals. Exit Impact v2 adds a second, independent view: the canonical pool's on-chain LP-control and reserve evidence. The two surfaces are reported together without pretending they describe the same route.

## Evidence surfaces

### Jupiter execution surface

For each fixed sell tier, Koschei records:

- requested USD notional;
- estimated proceeds;
- execution shortfall percentage;
- effective execution price versus the reference price;
- Jupiter-reported price impact;
- quote context slot;
- unique route labels.

The collector remains quote-only. It never requests a swap transaction and never signs, submits or custodies assets.

### Canonical LP surface

Exit Impact v2 projects the existing verified LP-control evidence needed to understand the canonical pool:

- pool address, program and pool type;
- control model and canonical-pool flag;
- LP read slot;
- reserve liquidity USD and its value source;
- dominant LP holder share/classification;
- creator relation and creator LP share;
- burned, locked and permanently locked shares;
- recent liquidity-movement status;
- concentrated-liquidity position enumeration status when applicable.

## Canonical reserve reference

When a verified canonical reserve USD value exists, each sell tier receives:

```text
requested_notional_usd / canonical_pool_reserve_liquidity_usd * 100
```

as `canonical_reserve_reference_pct`.

This is deliberately named a reference ratio, not "route consumed" or "pool drained". Jupiter can route across multiple venues and the current quote evidence does not prove that the canonical pool supplied the quoted execution. Koschei therefore never equates the canonical LP reserve with aggregate Jupiter route capacity.

## Observation slots

When both are available, each tier records the absolute spread between:

- the LP-control `read_slot`; and
- the Jupiter quote `context_slot`.

No arbitrary maximum-safe slot spread is introduced in this foundation. Missing slots remain missing rather than being estimated.

## Aggregate assessment

`impact_v2` summarizes measured values only:

- requested versus successfully quoted tier count;
- largest successfully quoted notional;
- worst observed execution shortfall;
- worst reference-price drop;
- worst Jupiter price impact;
- maximum canonical-reserve reference percentage;
- maximum quote context slot;
- maximum LP/quote observation-slot spread.

The status distinguishes complete quote+LP evidence, quote-only evidence, partial evidence, LP-reference-only evidence and unavailable evidence.

## Safety boundary

Exit Impact v2 does not add points to a risk score, downgrade a token, infer malicious intent from LP ownership, or assert that a Jupiter route used the canonical pool. It is an evidence surface for investigation and later benchmark work.

A later hardening phase can add route-address evidence or provider corroboration before making route-to-pool claims. Any future scoring policy must be separately versioned and tested rather than hidden inside this evidence builder.
