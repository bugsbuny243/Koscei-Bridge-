# Transaction Guard v3

Koschei Transaction Guard is a pre-signing, evidence-first Solana transaction assessment endpoint. It extends the original Transaction Firewall without changing the server-side no-custody boundary.

## Current mode

The Guard API remains read-only shadow infrastructure:

- it never signs a transaction
- it never submits a transaction
- it never stores the serialized transaction
- it returns `allow`, `warn`, `block` or `withhold`
- it stores only a transaction fingerprint, policy evidence, findings and sanitized simulation logs
- deterministic simulation failures remain explicit `block` decisions
- RPC/provider outages return `withhold` with HTTP 503

For applications that integrate the optional client SDK, `koschei-wallet-enforcement.js` can enforce those decisions locally before protected wallet calls:

- `block` and `withhold` never reach the wrapped wallet
- `warn` requires approval bound to the exact transaction fingerprint
- transaction bytes are checked again immediately before signing
- the signed transaction message is checked after signing
- incomplete evidence never becomes an implicit allow

This is an integration boundary, not universal wallet protection. A malicious dApp can bypass an optional SDK by calling the raw wallet provider. See [Transaction Guard Wallet Enforcement v1](transaction-guard-wallet-enforcement.md) for the exact boundary and integration contract.

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

## Evidence surfaces

Guard v3 combines:

- serialized transaction decoding, including v0 address lookup tables
- outer and inner program calls
- automatic pre/post SOL and token-account changes
- CPI asset flow and program-controlled vault candidates
- signed UI intent binding
- exact-address signed Threat History matches
- SPL Token and Token-2022 authority surface
- final simulated delegate, mint-authority, freeze-authority, owner and close-authority state when available
- Token-2022 permanent delegate, transfer fee and transfer-hook instructions
- a human-readable pre-signing explanation

Required evidence that cannot be completed produces `withhold`, not a safe claim.

## Program policy

- `expected_programs`: when supplied, every non-built-in invoked program must be expected.
- `required_programs`: each listed program must appear in the complete execution surface.
- `blocked_programs`: any invocation is a critical block finding.
- `TRANSACTION_GUARD_BLOCKED_PROGRAMS`: operator-level comma-separated denylist. A malformed configured entry fails closed with HTTP 503.

Program policy includes programs resolved from simulation logs, decoded transactions, CPI execution and Token-2022 transfer hooks. Only the log copy returned to clients is capped and sanitized.

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

`decimals` is caller-declared metadata. Raw integer amounts remain the enforcement source of truth.

## Decisions

- `allow`: simulation and every required evidence policy completed without a risk finding that changes the decision.
- `warn`: reviewable execution or policy evidence was found.
- `block`: deterministic simulation failure, dangerous instruction, blocked program, mint mismatch, critical amount-policy violation, dangerous authority capability, signed historical risk match or undeclared wallet-origin CPI exit.
- `withhold`: provider unavailable, response identity mismatch or required evidence incomplete.

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
TRANSACTION_GUARD_REQUIRE_SIGNED_INTENT=false
TRANSACTION_GUARD_REQUIRE_THREAT_HISTORY=false
TRANSACTION_GUARD_REQUIRE_CPI_FLOW=true
TRANSACTION_GUARD_REQUIRE_AUTHORITY_SURFACE=true
```

The Guard follows Koschei's canonical Solana RPC resolution order. Server-side transaction submission remains outside the product boundary; integrated applications may enforce Guard decisions locally through the strict wallet middleware.
