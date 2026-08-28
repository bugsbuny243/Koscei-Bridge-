# Webhook Delivery Engine

Koschei can deliver watchlist alerts to customer HTTPS endpoints through a persistent PostgreSQL queue.

## Security model

- HTTPS is required in production.
- Localhost, private networks, link-local addresses and cloud metadata destinations are rejected.
- DNS is checked when an endpoint is created and again before every connection.
- Redirect destinations are validated and limited to three hops.
- Endpoint secrets are generated with 256 bits of randomness.
- Secrets are encrypted at rest with AES-GCM using `WEBHOOK_ENCRYPTION_KEY`, falling back to the already-required `USER_SESSION_SECRET`.
- A secret is returned only when the endpoint is created or rotated.

## Signature verification

Every request includes:

```text
X-Koschei-Delivery-ID: DELIVERY_UUID
X-Koschei-Event-ID: EVENT_UUID
X-Koschei-Event: watchlist.alert.created
X-Koschei-Timestamp: UNIX_SECONDS
X-Koschei-Signature: v1=HEX_HMAC_SHA256
```

The signed bytes are:

```text
timestamp + "." + raw_request_body
```

Example pseudocode:

```text
expected = "v1=" + hex(hmac_sha256(secret, timestamp + "." + rawBody))
constant_time_compare(expected, X-Koschei-Signature)
```

Consumers should also reject timestamps outside a short replay window, such as five minutes.

## Delivery behavior

A database trigger creates one delivery row for each active endpoint that subscribes to `watchlist.alert.created`. The alert and delivery rows are committed in the same database transaction.

Successful responses are HTTP `2xx`.

Retryable failures:

- network and timeout errors
- HTTP 408
- HTTP 425
- HTTP 429
- HTTP 5xx

Retry schedule:

```text
1 minute
5 minutes
30 minutes
2 hours
8 hours
24 hours
```

After the configured attempt limit, or after a permanent HTTP 4xx response, the delivery moves to `dead_letter`. A customer can manually requeue it from the delivery console.

Twenty consecutive endpoint failures automatically pause the endpoint to protect Koschei and the customer system.

## Customer routes

All webhook-management and delivery-console routes require a verified customer session and active **Enterprise SaaS entitlement**. Webhook management itself does not consume a scan unit; the scans and watchlist operations that create security events are metered separately by their own route contracts.

```text
GET    /api/webhooks
POST   /api/webhooks
PATCH  /api/webhooks/{id}
DELETE /api/webhooks/{id}
POST   /api/webhooks/{id}/rotate-secret
POST   /api/webhooks/{id}/test
GET    /api/webhooks/deliveries
POST   /api/webhooks/deliveries/{id}/retry
```

The plain HTML management console is available at:

```text
/webhooks
```

## Payload

```json
{
  "id": "WATCHLIST_ALERT_UUID",
  "type": "watchlist.alert.created",
  "created_at": "2026-06-27T13:00:00Z",
  "data": {
    "watchlist_id": "WATCHLIST_UUID",
    "target": "SOLANA_MINT",
    "target_type": "token",
    "network": "solana-mainnet",
    "label": "Launch candidate",
    "event_type": "mint_authority_changed",
    "severity": "critical",
    "title": "Mint authority changed",
    "message": "A previously disabled authority is active.",
    "previous_value": "",
    "current_value": "AUTHORITY_ADDRESS",
    "evidence": {}
  }
}
```
