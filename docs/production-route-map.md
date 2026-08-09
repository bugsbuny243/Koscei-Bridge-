# Koschei ARVIS Production Route Map

This file describes routes that are wired into the current Go server boot chain.

The machine-readable source is `productionRouteInventory()` in `koschei/api/internal/http/route_inventory.go`, exposed to the owner command surface at `GET /api/owner/route-map`. CI contract tests compare that inventory with literal API registrations in the boot-chain route files. A route must not be documented as live when it is not registered.

## Public and system surface

- `GET /health`
- `GET /api/config`
- `GET /api/version`
- `GET /api/web3/health`
- `GET /api/web3/health/logs`
- `POST /api/analytics/event`
- `POST /api/arvis/preflight`
- `POST /api/token/scan`
- `GET /api/v1/risk/badge`
- `GET /api/public/impact`
- `GET /api/public/metrics`
- `GET /api/public/cases`
- `GET /api/public/soc/feed`
- `GET /api/public/token/status`
- `GET /api/public/token/readiness`
- `GET /api/public/scan-history`
- `POST /api/public/transaction-simulate`
- `GET /api/agent/health`
- `POST /api/agent/wallet-score`
- `POST /api/agent/risk-summary`
- `POST /api/agent/metadata-template`
- `POST /api/agent/chain-health`

Some routes in this group are public while others still enforce their own authentication or database requirements. The route inventory records boot-chain presence; handler policy remains authoritative for the final access decision.

## Identity and account access

- `POST /api/auth/provision`
- `POST /api/auth/register`
- `POST /api/auth/login`
- `GET /api/auth/neon-login`
- `GET /api/auth/neon-register`
- `GET /api/auth/neon-callback`
- `GET /api/me`
- `/api/account/api-keys`
- `/api/account/api-keys/`
- `POST /api/auth/wallet/challenge`
- `POST /api/auth/wallet/verify`
- `GET /api/auth/wallet/status`
- `POST /api/auth/wallet/unlink`
- `GET /api/auth/token-access`
- `GET /api/auth/premium-access`

Developer API keys remain credentials. They do not bypass live KOSCH eligibility checks.

## Customer Radar and reports

- `POST /api/v1/token/extensions`
- `POST /api/v1/address-poisoning/check`
- `POST /api/v1/radar/check`
- `POST /api/v1/radar/jobs`
- `GET /api/v1/radar/jobs/`
- `GET /api/v1/radar/detail`
- `GET /api/v1/radar/feed`
- `GET /api/v1/radar/creator-intelligence`
- `GET /api/v1/radar/actor-intelligence`
- `GET /api/v1/radar/graph`
- `GET /api/v1/radar/exposure`
- `POST /api/v1/radar/court`
- `POST /api/jobs/token-scan`
- `GET /api/jobs/`

These routes are session-authenticated and apply the configured KOSCH tier and quota policy.

## Developer API

- `POST /api/v1/scan/token`
- `GET /api/v1/usage`
- `POST /api/v1/shield/preflight`
- `POST /api/v1/shield/transaction`
- `POST /api/v1/shield/address-poisoning`

The transaction route is the evidence-first Transaction Guard. It may return `allow`, `warn`, `block` or `withhold`; missing required evidence never becomes an `allow` result.

## Immutable dossier surface

- `POST /api/v1/dossier/`
- `GET /dossier/`
- `GET /case/`
- `GET /api/public/cases`
- `GET /api/public/soc/feed`
- `POST /api/owner/dossier/publications`
- `POST /api/owner/arvis/acceptance`

Dossier publication transports immutable evidence. It does not create evidence or change the deterministic verdict.

## Watchlist and webhook surface

- `/api/watchlist`
- `POST /api/watchlist/refresh`
- `/api/watchlist/alerts`
- `/api/watchlist/`
- `/api/webhooks`
- `/api/webhooks/`
- `/api/webhooks/security-alerts`
- `/api/webhooks/deliveries`
- `/api/webhooks/deliveries/`

Watchlist routes require the configured Pro access policy. Webhook management uses the Enterprise access policy. Security subscriptions include durable ARVIS and Transaction Guard alert delivery.

## Owner operations

The owner surface includes command-center, operations, ARVIS/radar jobs, creator and actor intelligence, funding-corpus warmup, Defense investigation tracks, route-map inspection, KOSCH access inspection, security events, user operations, owner brain/chat and dossier publication controls.

The exact current list is returned by `GET /api/owner/route-map`; do not maintain a second hand-written owner list in product code.

## Defense OS — opt-in only

Defense OS route registration occurs only when:

```text
KOSCHEI_DEFENSE_OS_ENABLED=true
```

Registered owner-only paths under that gate are:

- `/api/owner/defense/artifacts`
- `/api/owner/defense/knowledge`
- `/api/owner/defense/lab`
- `/api/owner/defense/deployment`
- `/api/owner/defense/source-import`
- `/api/owner/defense/worker-jobs`
- `/api/owner/defense/reproduction`
- `/api/owner/defense/sentinel`
- `/api/owner/defense/harness`
- `/api/owner/defense/harness-execution`
- `/api/owner/defense/harness-materialization`
- `/api/owner/defense/litesvm-execution`

These are lab/reproduction surfaces and remain separate from ARVIS verdict authority.

## Route hygiene contract

- Boot-chain registration defines whether a handler is live.
- `productionRouteInventory()` must contain every literal `/api/*` boot-chain registration and must not retain removed routes.
- The database-optional allowlist must not contain an unregistered API path.
- Documentation must not resurrect legacy Shopier, Paddle, package-purchase or owner-payment routes that are no longer registered.
- Evidence-backed outputs are signed only when verified evidence exists.
- Missing, malformed or unavailable evidence fails closed rather than becoming a safety signal.
