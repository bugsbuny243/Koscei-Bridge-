# Transaction Guard v2

Koschei Transaction Guard is a pre-signing, evidence-first Solana transaction assessment endpoint. It extends the original Transaction Firewall without changing the no-custody boundary.

## Current mode

The release runs in shadow mode:

- it never signs a transaction
- it never submits a transaction
- it never stores the serialized transaction
- it never blocks a wallet automatically
- it returns `allow`, `warn`, `block` or `withhold`
- it stores only a transaction fingerprint, policy evidence, findings and sanitized simulation logs
- deterministic simulation failures remain explicit `block` decisions
- RPC/provider outages return `withhold` with HTTP 503

## Endpoint

```http
POST /api/v1/shield/transaction
X-API-Key: YOUR_KEY
Content-Type: application/json

{
  "transaction": "BASE64_SERIALIZED_TRANSACTION",
  "encoding": "base64",
  "network": "solana-mainnet",
  "wallet": "OPTIONAL_WALLET",
  "expected_programs": [
    "JUP6LkbZbjS1jKKwapdHNy74zcZ3tLUZoi5QNyVTaV4"
  ],
  "required_programs": [],
  "blocked_programs": [],
  "accounts": [
    {
      "address": "INPUT_TOKEN_ACCOUNT",
      "mint": "INPUT_MINT",
      "role": "input",
      "maximum_spend_raw": "1000000"
    },
    {
      "address": "OUTPUT_TOKEN_ACCOUNT",
      "mint": "OUTPUT_MINT",
      "role": "output",
      "minimum_receive_raw": "950000",
      "quoted_receive_raw": "1000000",
      "max_slippage_bps": 500
    }
  ]
}
```

All request-supplied wallet, program, account and mint identities are decoded as Solana public keys. A malformed policy is rejected rather than silently weakened.

## Program policy

- `expected_programs`: when supplied, every non-built-in invoked program must be expected.
- `required_programs`: each listed program must appear in the complete simulation log surface.
- `blocked_programs`: any invocation is a critical block finding.
- `TRANSACTION_GUARD_BLOCKED_PROGRAMS`: operator-level comma-separated denylist. A malformed configured entry fails closed with HTTP 503.

Program policy reads all simulation logs. Only the copy returned to clients is capped and sanitized.

## Account policy

Guard account evidence is accepted only when the account is owned by SPL Token or Token-2022 and has a valid token-account layout.

For each guarded account, Koschei reads:

- raw mint bytes
- raw pre-simulation amount
- raw post-simulation amount
- signed delta
- spent amount
- received amount

When `mint` is supplied, it is compared with the raw token-account mint before spend, receive or slippage rules are evaluated. A mismatch blocks the transaction.

Normal account lifecycle is supported:

- a missing pre-state is treated as zero only for an `output` account created by the transaction
- a missing post-state is treated as zero only for an `input` account closed by the transaction
- missing sides for other roles remain `withhold`

`decimals` is caller-declared metadata and is returned as `declared_decimals` with `decimals_verified=false`. Raw integer amounts are the enforcement source of truth.

## Decisions

- `allow`: simulation and every requested evidence policy completed without a finding.
- `warn`: reviewable execution or policy evidence was found.
- `block`: deterministic simulation failure, dangerous instruction, blocked program, mint mismatch, or critical amount-policy violation.
- `withhold`: provider unavailable or required evidence incomplete.

A missing signal never means safe.

## Durable alerts

Every non-`allow` Guard decision creates a tenant-scoped `transaction.guard.decision` event when the database is available.

Enterprise webhook subscriptions use:

```http
POST /api/webhooks/security-alerts
Authorization: Bearer CUSTOMER_SESSION
Content-Type: application/json

{
  "endpoint_id": "WEBHOOK_ENDPOINT_UUID",
  "enabled": true,
  "event_types": ["transaction.guard.decision"]
}
```

Supported event types:

- `security.alert.created` — wildcard for all security alerts
- `arvis.verdict.created`
- `transaction.guard.decision`

Security subscriptions are stored separately from watchlist webhook event settings, so ordinary webhook edits do not erase them.

## System channels

High and critical events can also enter the retryable Telegram/Discord outbox.

```env
TELEGRAM_BOT_TOKEN=
TELEGRAM_CHAT_ID=
DISCORD_WEBHOOK_URL=https://discord.com/api/webhooks/...
SECURITY_ALERT_MIN_SEVERITY=high
```

Provider URLs and credentials are never persisted in delivery errors.

## Configuration

```env
KOSCHEI_TRANSACTION_FIREWALL_ENABLED=true
TRANSACTION_GUARD_BLOCKED_PROGRAMS=
```

The Guard follows Koschei's canonical Solana RPC resolution order. Automatic transaction submission or enforcement is not part of this release.
