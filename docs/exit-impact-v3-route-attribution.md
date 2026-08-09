# Koschei Exit Impact v3 — Route Address Attribution

Status: evidence-layer upgrade; informational only and not connected to risk scoring or final verdicts.

## Goal

Exit Impact v2 keeps Jupiter execution quotes and the canonical pool reserve/control surface separate. V3 adds exact route identity when Jupiter exposes an AMM account key in the returned quote plan.

The rule is deliberately narrow:

```text
returned routePlan.swapInfo.ammKey == canonical LP pool address
```

Only that exact address equality can produce `canonical_pool_observed_in_returned_route_plan`.

## Quote-plan evidence

Each fixed exit tier stores the returned quote-plan steps as bounded evidence:

- `amm_key` — Jupiter-returned AMM/pool account identity when it is a valid Solana address;
- `label` — Jupiter route label;
- `percent` — route-plan share from the current Metis v1 response.

Invalid or malformed AMM keys are discarded before attribution. Duplicate AMM identities are deduplicated for aggregate counts.

## Canonical-pool attribution

Per quoted tier, Koschei reports one of:

- `canonical_pool_observed_in_returned_route_plan` — the exact canonical pool address appears in the returned AMM keys;
- `canonical_pool_not_observed_in_returned_route_plan` — valid AMM keys were returned, but none equal the canonical pool address;
- `route_keys_unavailable` — the quote did not expose a usable AMM identity;
- `canonical_pool_unavailable` — route keys exist but there is no verified canonical pool address to compare;
- `quote_unavailable` — there is no usable quote for the tier.

A non-match is intentionally not phrased as “the pool was not used.” It only means the canonical pool was not present in that returned quote plan. A later quote or actual execution can differ.

## Aggregate route evidence

Exit Impact v3 adds:

- number of quoted tiers with usable AMM-key attribution;
- number of tiers whose returned plan contains the canonical pool;
- whether the canonical pool appears in any returned plan;
- route-attribution coverage: `complete`, `partial`, or `unavailable`.

These values remain evidence. They do not modify a token grade, risk index or security verdict.

## Jupiter API-key boundary

`JUPITER_API_KEY` is sent only when the exact request hostname is:

```text
api.jup.ag
```

A custom `JUPITER_QUOTE_URL`, localhost test server or lookalike hostname such as `api.jup.ag.evil.example` never receives the configured Jupiter API key.

When the official `api.jup.ag` quote endpoint is selected but `JUPITER_API_KEY` is missing, collection stops with:

```text
jupiter_api_key_unavailable
```

before any Jupiter HTTP request is attempted. This avoids predictable unauthorized calls and makes provider configuration failure explicit.

## Read-only boundary

The collector still permits only a `/quote` endpoint, uses `ExactIn`, and never requests a swap transaction. Koschei does not sign, submit, mutate or custody assets.

`amm_key` attribution describes an unexecuted quote plan. It is not transaction execution evidence.

## Swap V2 migration

The current collector keeps the existing Metis Swap v1 quote transport in this PR so route-attribution semantics can be reviewed independently. Jupiter documents Metis v1 as no longer actively maintained and recommends Swap V2 for new integrations.

A separate migration should adapt V2 response semantics behind tests rather than silently changing provider transport here. In particular, route-plan weighting may expose `bps` as the canonical precision while retaining legacy-compatible percentage fields.

## Compatibility

The existing JSON envelope remains `impact_v2` to avoid breaking current consumers, while the embedded assessment reports:

```text
version = koschei-exit-impact-v3
```

A future breaking API version may rename the envelope explicitly, but this change keeps current response consumers source-compatible.
