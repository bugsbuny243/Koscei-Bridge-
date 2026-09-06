# Koschei ARVIS API Reference

This document separates registered server routes from product-readiness claims. Boot-chain presence is contract-tested against `productionRouteInventory()`; see `docs/production-route-map.md` for the complete route map. A registered route is an integration contract, not by itself a claim that the surrounding ARVIS module has completed production validation.

## Authentication

### Customer session routes

Use:

```http
Authorization: Bearer CUSTOMER_SESSION_TOKEN
```

Operational customer routes authorize through one commercial entitlement: **Professional**. Paid output-capacity enforcement remains server-owned. Missing, expired or inconsistent entitlement state fails closed.

KOSCH holdings, wallet balances, historical token tiers and `token_access_snapshots` do not grant, upgrade or discount commercial access.

Authentication: customer session + active Professional entitlement.

### Developer API routes

Use either:

```http
X-API-Key: ARVIS_API_KEY
```

or:

```http
Authorization: Bearer ARVIS_API_KEY
```

Developer API keys are identity credentials. Registered developer routes require an active Professional entitlement and remain subject to per-minute rate limits, configured usage quotas, runtime feature gates and endpoint-specific readiness/evidence rules. Credential eligibility is not a promise that every integration surface has completed production validation.

Authentication: developer API key + active Professional entitlement.

---

## Professional compatibility routes

The following historical paths remain registered for client compatibility, but they no longer imply anonymous/free operational analysis. The HTTP readiness boundary applies customer authentication, active Professional entitlement and the output ledger before the existing handlers execute.

```text
POST /api/arvis/preflight
POST /api/token/scan
```

Public proof, health and documentation surfaces remain separate and do not execute a customer investigation.

---

## Registered: POST /api/v1/radar/check

Runs an evidence-backed Radar check for a supported Solana target.

Authentication: customer session + active Professional entitlement.

```json
{
  "target": "SOLANA_TARGET",
  "network": "solana-mainnet",
  "mode": "developer_test"
}
```

The result may include the deterministic verdict, evidence arms, signature metadata, limitations and charge status. Missing required evidence is not converted into a low-risk result.

---

## Registered: POST /api/v1/radar/jobs

Creates a canonical asynchronous investigation job.

Authentication: customer session + active Professional entitlement.

The canonical worker accepts supported token mint, wallet or token-account targets and continues independently of the originating HTTP request. Use `GET /api/v1/radar/jobs/` with the job identifier path suffix to retrieve the result.

---

## Registered Radar read surfaces

Authentication: customer session + active Professional entitlement.

```text
GET /api/v1/radar/detail
GET /api/v1/radar/feed
GET /api/v1/radar/creator-intelligence
GET /api/v1/radar/actor-intelligence
GET /api/v1/radar/graph
GET /api/v1/radar/exposure
POST /api/v1/radar/court
```

These surfaces remain subject to ARVIS production-readiness validation and must not be represented as complete solely because a route is registered. The court consumes existing evidence and deterministic results; narrative/model output cannot create evidence or alter the authoritative verdict.

---

## Registered developer route: POST /api/v1/scan/token

Queues an API-key-protected Solana token scan.

Authentication: developer API key + active Professional entitlement.

```json
{
  "mint": "TOKEN_MINT",
  "network": "solana-mainnet",
  "include_ai": false
}
```

A typical accepted response contains a request identifier, queued status and usage reservation metadata. Failed evidence collection must not be charged as a successful evidence-backed output.

---

## Registered developer route: POST /api/v1/shield/preflight

Runs a security preflight check for a target, token mint, address or transaction context.

Authentication: developer API key + active Professional entitlement.

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

## Registered developer route: POST /api/v1/shield/transaction

Runs the evidence-first Transaction Guard before signing.

Authentication: developer API key + active Professional entitlement.

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

Possible customer actions are `allow`, `warn`, `block`, or `withhold`. Provider failure, incomplete required evidence or an unresolved required execution surface cannot silently become `allow`.

See `docs/transaction-firewall.md` for the detailed Guard contract.

---

## Registered developer route: POST /api/v1/shield/state-recheck

Rechecks state-bound Transaction Guard evidence before a previously evaluated decision is relied on again.

Authentication: developer API key + active Professional entitlement.

The recheck route does not turn stale, missing or changed state into an `allow` decision.

---

## Registered defense validation route: POST /api/v1/defense/validation

Evaluates whether a declared execution-integrity defense passed an isolated attack/benign validation scenario.

Authentication: developer API key + active Professional entitlement.

The request carries the scenario contract, control/collector trust configuration, isolated execution-containment receipt, execution proof, exact approved/candidate canonical Safe action bytes and, when required, the independent collector's signed observation.

The server recomputes scenario hash, containment/proof bindings and Ed25519 observation authentication before evidence can become VERIFIED. Caller-asserted `verified` state is not accepted. The route does not execute arbitrary commands, submit mainnet transactions, mutate production controls or use AI as verdict authority. Missing observations remain incomplete instead of becoming a pass.

See `docs/defense-validation-api.md` for the complete request/evidence boundary.

---

## Registered developer route: POST /api/v1/shield/address-poisoning

Runs API-key-protected address-poisoning analysis.

Authentication: developer API key + active Professional entitlement.

A customer-session equivalent is registered at `POST /api/v1/address-poisoning/check` and uses the same Professional commercial boundary.

---

## Registered developer route: GET /api/v1/usage

Returns recent developer API usage events.

Authentication: developer API key + active Professional entitlement.

Usage records may include endpoint, status, reserved credits, charged credits, error code and completion timestamps.

---

## Registered Token-2022 analysis

```text
POST /api/v1/token/extensions
```

Authentication: customer session + active Professional entitlement.

The current surface recognizes extension and authority behaviors including transfer hooks, permanent delegates, transfer-fee configuration, default account state, mint close authority, pausable behavior, non-transferability, confidential-transfer visibility limits and related compatibility evidence. Unsupported or unresolved extension state must remain explicit.

---

## Registered watchlists and security webhooks

These are customer-session operations and use the Professional entitlement. Their registration does not override ARVIS feature-readiness labeling.

```text
/api/watchlist
POST /api/watchlist/refresh
/api/watchlist/alerts
/api/watchlist/

/api/webhooks
/api/webhooks/
/api/webhooks/security-alerts
/api/webhooks/deliveries
/api/webhooks/deliveries/
```

Signed medium-or-higher ARVIS verdicts and non-`allow` Transaction Guard decisions can enter the durable alert pipeline when the relevant runtime features are enabled. Webhook delivery transports an existing deterministic result; delivery does not create or modify a grade.

---

## Registered immutable dossier export

```text
POST /api/v1/dossier/
```

Owner credentials retain their explicit administrative path. Customer-session and developer-key export paths use the Professional commercial boundary. KOSCH holdings and historical token-access snapshots never authorize export.

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
- provider-neutral third-party Defense Validation adapters;
- multi-provider Evidence Court API for critical evidence quorum;
- signed Evidence Receipt verification surface;
- dedicated LP-control and exit-impact simulation API.

Roadmap names must not be presented as live endpoints before boot-chain registration. Registered routes likewise must not be described as production-complete until their feature-readiness validation is complete.
