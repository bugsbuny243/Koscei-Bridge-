# Persistent Watchlist and Change Alerts

Koschei Watchlist stores customer-owned Solana token targets and compares each new scan with the previous verified snapshot.

## Technology

- Go API
- Neon PostgreSQL persistence
- plain HTML/CSS/browser JavaScript at `/watchlist`
- no frontend framework
- no private key or seed phrase collection

## Routes

All watchlist routes require a verified Koschei customer session and an active **Professional SaaS plan**. They use the metered watchlist route gate, so paid output-capacity enforcement remains server-owned.

```text
GET    /api/watchlist
POST   /api/watchlist
PATCH  /api/watchlist/{id}
DELETE /api/watchlist/{id}
POST   /api/watchlist/{id}/refresh
POST   /api/watchlist/refresh?limit=5
GET    /api/watchlist/alerts
POST   /api/watchlist/alerts
```

Webhook management is governed by the same Professional entitlement; there is no separate paid Enterprise tier.

## Add a target

```json
{
  "target": "SOLANA_TOKEN_MINT",
  "target_type": "token",
  "network": "solana-mainnet",
  "label": "Launch candidate",
  "alert_threshold": 50
}
```

`alert_threshold` is a minimum security score. An alert is created when a previously healthy score crosses below this floor. The create handler treats `0` as the server default threshold; the current web console therefore asks for an explicit value from `1` to `100` so the user does not mistake zero for a literal zero threshold.

## Current alert rules

- security score drops by at least 15 points
- security score crosses below the configured floor
- mint authority changes
- freeze authority changes
- an authority that was previously disabled becomes active
- largest-holder concentration increases by at least 10 percentage points
- raw token supply changes

The first successful scan creates the baseline and does not create an alert.

## Refresh behavior

Manual refresh remains available for individual targets and bounded batches. The customer batch endpoint accepts a requested limit and clamps it to the server maximum of ten targets per call, refreshing the oldest active targets first.

Koschei also contains a background watchlist monitor, but it runs only when **both** automatic background scanning and the watchlist monitor are explicitly enabled. `WATCHLIST_MONITOR_ENABLED` gates that worker; if the worker is disabled, manual refresh remains available. The worker claims due active targets and uses `next_check_at` without changing the customer API contract.

## Storage

`watchlist_targets` stores:

- customer ownership
- target and label
- active or paused status
- security floor
- latest verified snapshot
- last and next check timestamps

`watchlist_alerts` stores immutable before/after values, severity, evidence and read state. Deleting a target deletes its alert history through the foreign-key relationship.

## Compatibility

The feature remains account-scoped and additive to the evidence engine. Paid watchlist authorization is based only on the active Professional SaaS entitlement. KOSCH holder balances and removed package labels do not grant or upgrade watchlist access.
