# Jupiter Swap V2 Quote-Only Adapter

Status: Exit Liquidity transport migration with explicit legacy override compatibility.

## Default transport

When `JUPITER_QUOTE_URL` is not configured, Exit Liquidity uses:

```text
GET https://api.jup.ag/swap/v2/order
```

with `inputMint`, `outputMint`, `amount` and `swapMode=ExactIn` only.

Koschei deliberately omits `taker`, routing constraints and slippage overrides from the default V2 request. Without a taker, the endpoint is used as quote-only evidence and must not return an executable transaction.

If a V2 quote-only response unexpectedly contains a non-null `transaction`, Koschei rejects the response rather than accepting executable material into the evidence path.

## Explicit legacy override

An explicitly configured:

```text
JUPITER_QUOTE_URL=.../quote
```

continues to select the existing Metis v1/custom quote adapter. This is a compatibility override, not an automatic fallback.

Koschei does not silently fall back from Swap V2 to Metis v1 after a V2 error. Provider failures remain explicit evidence gaps.

A custom V2 endpoint can be supplied with:

```text
JUPITER_ORDER_URL=.../order
```

The read-only path validator permits HTTPS endpoints and HTTP loopback endpoints for tests/development.

## API-key boundary

`JUPITER_API_KEY` is attached only when the exact request hostname is `api.jup.ag`. Custom, localhost and lookalike hosts do not receive it.

Selecting an official `api.jup.ag` quote/order endpoint without `JUPITER_API_KEY` fails before provider HTTP access with `jupiter_api_key_unavailable`.

## Price-impact normalization

The internal Exit Liquidity contract stores one adverse percentage-point value.

For Swap V2:

- `priceImpact` is interpreted directly in percentage points;
- only negative price impact is treated as adverse, stored as its positive magnitude;
- a positive value is not converted into a risk/shortfall penalty;
- the deprecated `priceImpactPct` string is used only as a compatibility fallback when `priceImpact` is zero, using the legacy ratio-to-percent conversion.

For the explicit Metis v1 adapter, the historical `priceImpactPct` ratio continues to be multiplied by 100 before entering the shared evidence contract.

## Route evidence

Swap V2 route-plan evidence preserves:

- `ammKey`;
- label;
- percent;
- basis points (`bps`);
- USD route value where supplied.

The existing Exit Impact v3 exact-address attribution consumes the same AMM-key identity contract. Route-plan evidence describes the returned quote only and is not proof of later execution.

## Observation slots

Metis v1 quote responses can carry `contextSlot`, which remains preserved.

The V2 adapter does not invent a Solana context slot when the `/order` response does not provide one. Existing downstream slot-spread logic therefore remains evidence-safe: missing quote slots stay missing.

## Non-custodial boundary

This adapter never:

- supplies a taker wallet to the default V2 order request;
- requests `/execute`;
- signs a transaction;
- submits a transaction;
- mutates or custodies assets.

Exit Liquidity remains an evidence-only, read-only quote surface.

## Separate follow-up

`collectJupiterMarketContext` still has its own Price v3 and legacy top-holder quote transport. It should be moved to the same trusted Jupiter client/adapter layer in a separate change so this migration remains reviewable and reversible.
