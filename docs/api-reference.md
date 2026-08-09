# Koschei ARVIS API Reference

This document separates current production routes from planned expansion. Boot-chain presence is contract-tested against `productionRouteInventory()`; see `docs/production-route-map.md` for the complete route map.

## Authentication

### Customer session routes

Use:

```http
Authorization: Bearer CUSTOMER_SESSION_TOKEN
```

Premium customer routes also enforce the configured KOSCH tier and quota policy.

### Partner API routes

Use either:

```http
X-API-Key: ARVIS_API_KEY
```

or:

```http
Authorization: Bearer ARVIS_API_KEY
```

Developer API keys are identity credentials and remain subject to live KOSCH eligibility, per-minute rate limits and configured usage quotas.

---

## Live: POST /api/v1/radar/check

Runs an evidence-backed Radar check for a supported Solana target.

Authentication: customer session + eligible KOSCH tier.

```json
{
  "target": "SOLANA_TARGET",
  "network": "solana-mainnet",
  "mode": "developer_test"
}
```

The result may include the deterministic verdict, evidence arms, signature metadata, limitations and charge status. Missing required evidence is not converted into a low-risk result.

---

## Live: POST /api/v1/radar/jobs

Creates a canonical asynchronous investigation job.

Authentication: customer session + eligible KOSCH tier.

The canonical worker accepts supported token mint, wallet or token-account targets and continues independently of the originating HTTP request.

Use `GET /api/v1/radar/jobs/` with the job identifier path suffix to retrieve the result.

---

## Live Radar read surfaces

Authentication: customer session + configured KOSCH tier.

```text
GET /api/v1/radar/detail
GET /api/v1/radar/feed
GET /api/v1/radar/creator-intelligence
GET /api/v1/radar/actor-intelligence
GET /api/v1/radar/graph
GET /api/v1/radar/exposure
POST /api/v1/radar/court
```

The court surface consumes existing evidence and deterministic results. Narrative or model output cannot create evidence or alter the authoritative verdict.

---

## Live: POST /api/v1/scan/token

Queues an API-key-protected Solana token scan.

Authentication: developer API key + live KOSCH eligibility.

```json
{
  "mint": "TOKEN_MINT",
  "network": "solana-mainnet",
  "include_ai": false
}
```

A typical accepted response contains a request identifier, queued status and usage reservation metadata. Failed evidence collection must not be charged as a successful evidence-backed output.

---

## Live: POST /api/v1/shield/preflight

Runs a security preflight check for a target, token mint, address or transaction context.

Authentication: developer API key + live KOSCH eligibility.

```json
{
  "target": "SOLANA_TARGET",
  "wallet": "OPTIONAL_WALLET",
  "network": "solana-mainnet",
  "context": {
    "surface": "wallet_warning"
  }
}
```

The response may include action, grade, deterministic verdict metadata, recommendation, signature metadata and module-level evidence quality.

---

## Live: POST /api/v1/shield/transaction

Runs the evidence-first Transaction Guard before signing.

Authentication: developer API key + live KOSCH eligibility.

```json
{
  "transaction": "BASE64_SERIALIZED_TRANSACTION",
  "encoding": "base64",
  "network": "solana-mainnet",
  "wallet": "OPTIONAL_WALLET",
  "expected_programs": [],
  "required_programs": [],
  "blocked_programs": [],
  "accounts": []
}
```

Current Guard processing can evaluate decoded transaction structure, address lookup tables, simulation evidence, inner-instruction/CPI flow, token-account ownership and balance deltas, authority surfaces, Token-2022 transfer-hook relationships, threat-history context and signed UI intent when supplied.

Possible customer actions are:

- `allow` — all required evidence completed without a blocking finding;
- `warn` — reviewable execution or policy evidence exists;
- `block` — a deterministic policy violation or dangerous execution signal exists;
- `withhold` — required evidence could not be completed.

Provider failure, incomplete required evidence or an unresolved required execution surface cannot silently become `allow`.

See `docs/transaction-firewall.md` for the detailed Guard contract.

---

## Live: POST /api/v1/shield/address-poisoning

Runs API-key-protected address-poisoning analysis.

Authentication: developer API key + live KOSCH eligibility.

A session-authenticated customer equivalent is also registered at `POST /api/v1/address-poisoning/check`.

---

## Live: GET /api/v1/usage

Returns recent developer API usage events.

Authentication: developer API key + live KOSCH eligibility.

Usage records may include endpoint, status, reserved credits, charged credits, error code and completion timestamps.

---

## Live Token-2022 analysis

```text
POST /api/v1/token/extensions
```

Authentication: customer session + eligible KOSCH tier.

The current Token-2022 surface recognizes extension and authority behaviors including transfer hooks, permanent delegates, transfer-fee configuration, default account state, mint close authority, pausable behavior, non-transferability, confidential-transfer visibility limits and related compatibility evidence. Unsupported or unresolved extension state must remain explicit.

---

## Live watchlists and security webhooks

These are customer-session routes, not developer-API-key routes.

Pro watchlist surface:

```text
/api/watchlist
POST /api/watchlist/refresh
/api/watchlist/alerts
/api/watchlist/
```

Enterprise webhook surface:

```text
/api/webhooks
/api/webhooks/
/api/webhooks/security-alerts
/api/webhooks/deliveries
/api/webhooks/deliveries/
```

Signed medium-or-higher ARVIS verdicts and non-`allow` Transaction Guard decisions can enter the durable alert pipeline. Webhook delivery transports an existing deterministic result; delivery does not create or modify a grade.

---

## Live immutable dossier export

```text
POST /api/v1/dossier/
```

Dossier export operates on existing evidence/snapshots and preserves provenance, limitations and publication boundaries. Public discovery surfaces include `GET /api/public/cases` and `GET /api/public/soc/feed`.

---

## Signed verdict trust rule

Consumers should treat a verdict as final only when the response contract marks it signed by the deterministic verdict engine. Clients should inspect the evidence, ruleset version, triggered rules, decision path, source freshness and limitations rather than relying on a single display score.

When verified evidence is unavailable, ARVIS withholds the authoritative verdict instead of fabricating a grade.

---

## Planned expansion — not production routes yet

The following remain roadmap work until they are registered, tested and added to the production route contract:

- dedicated wallet-specific developer API route;
- dedicated sybil/campaign-cluster batch API;
- multi-provider Evidence Court API for critical evidence quorum;
- State Witness / state-bound pre-signing receipt API;
- signed Evidence Receipt verification surface;
- dedicated LP-control and exit-impact simulation API.

Roadmap names must not be presented as live endpoints before boot-chain registration.
