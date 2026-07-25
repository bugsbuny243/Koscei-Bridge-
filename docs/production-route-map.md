# Koschei ARVIS Production Route Map

This file tracks routes that are wired into the Go server boot chain.

## Server boot groups

`koschei/api/internal/http/server.go` currently registers these groups:

- core routes
- account routes
- owner routes
- Defense OS routes
- public product routes
- developer API routes
- immutable dossier routes
- watchlist and webhook routes
- static public pages

## Core routes

- `GET /health`
- `GET /api/config`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/me`
- `GET /api/me/package`
- `GET /api/member/summary`
- `POST /api/payments/request`
- `POST /api/shopier/webhook`
- `POST /api/arvis/preflight`
- `GET /api/public/impact`
- `GET /api/public/metrics`
- `GET /api/public/tool-prices`
- `GET /api/web3/health`
- `GET /api/web3/health/logs`
- `POST /api/analytics/event`
- `GET /api/agent/health`
- `POST /api/agent/wallet-score`
- `POST /api/agent/risk-summary`
- `POST /api/agent/metadata-template`
- `POST /api/agent/chain-health`

## Account and access routes

- `GET /api/account/api-keys`
- `POST /api/account/api-keys`
- `POST /api/account/api-keys/{id}/revoke`
- `POST /api/auth/wallet/challenge`
- `POST /api/auth/wallet/verify`
- `GET /api/auth/wallet/status`
- `POST /api/auth/wallet/unlink`
- `GET /api/auth/token-access`
- `GET /api/auth/premium-access`

## Radar and report routes

- `GET /api/rug-radar/feed`
- `GET /api/v1/risk/badge`
- `GET /api/v1/radar/feed`
- `POST /api/v1/radar/check`
- `GET /api/v1/radar/graph`
- `GET /api/v1/radar/exposure`

## Developer API routes

These routes use API-key auth and API rate limits.

- `POST /api/v1/scan/token`
- `GET /api/v1/usage`
- `POST /api/v1/shield/preflight`
- `POST /api/v1/shield/transaction`

## Immutable dossier routes

- `POST /api/v1/dossier/{target}` creates or retrieves an immutable export from an existing signed snapshot. Creation accepts owner credentials, an eligible Enterprise session or an eligible Enterprise API key. It never rescans missing evidence.
- `GET /dossier/{case-ref}` is a public, account-free and KOSCH-free HTML evidence page backed by the immutable bundle.

Token and wallet actor cases share the `koschei-dossier-v1` envelope. Wallet cases retain the ordered `AC-01` through `AC-10` acceptance result, evidence-labelled created-token history, funding origin, cross-token observations, evidence log and section-local limitations.

## Watchlist routes

These routes use customer session auth and active entitlement checks.

- `/api/watchlist`
- `/api/watchlist/refresh`
- `/api/watchlist/alerts`
- `/api/watchlist/{id}`

## Webhook routes

These routes use customer session auth and active entitlement checks.

- `/api/webhooks`
- `/api/webhooks/{id}`
- `/api/webhooks/deliveries`
- `/api/webhooks/deliveries/{id}`

## Static public pages

The static server serves files from `koschei/api/public`.

- `/` serves `index.html`
- `/page` serves `page.html` when present
- unknown non-API paths fall back to `index.html`
- unknown `/api/*` paths return not found

## Route hygiene rules

- A handler is not considered live until it is registered in the server boot chain.
- Documentation must not call a route live unless it is registered.
- Customer routes should use session auth.
- Partner routes should use API-key auth.
- Premium routes should check active entitlement.
- Evidence-backed outputs should be signed only when verified evidence exists.
- Public dossier pages transport immutable evidence and never create or alter a verdict.
