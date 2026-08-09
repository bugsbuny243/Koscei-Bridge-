# Trusted Jupiter Market Client

Status: trust-boundary foundation for Jupiter market-context calls.

## Goal

Koschei already applies an exact-host API-key policy to Exit Liquidity. Market-context collection also calls Jupiter Price v3 and quote surfaces, so those paths must not invent a separate secret-handling policy.

This foundation provides one read-only GET helper with the same trust rule:

- exact hostname `api.jup.ag` may receive `JUPITER_API_KEY`;
- custom endpoints, localhost and lookalike domains never receive it;
- an official `api.jup.ag` request without `JUPITER_API_KEY` fails before HTTP transport;
- HTTPS is required except for loopback HTTP used by local tests;
- Price endpoints are separately validated as read-only `/price` or `/price/v3` paths.

## Why this is separate from the Swap V2 migration

Exit Liquidity transport and broader market-context transport are intentionally separated so each change remains independently reviewable and reversible.

The next integration phase will route:

- Jupiter Price v3 through this trusted GET helper;
- top-holder sell-impact quoting through the shared Swap V2 quote-only adapter, while preserving explicit legacy/custom overrides.

## Secret boundary

The client never sends `JUPITER_API_KEY` based on suffix or substring matching. A host such as:

```text
api.jup.ag.evil.example
```

is not trusted.

Official-host missing-key failure occurs before the configured HTTP transport is invoked. This prevents predictable unauthorized provider traffic and makes configuration gaps explicit.

## Read-only boundary

This client only performs GET requests and does not sign, submit, execute or custody transactions. Swap execution remains outside this component.
