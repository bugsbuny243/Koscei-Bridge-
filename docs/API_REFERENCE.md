# Public API Reference

This document covers the first externally documented Koschei ARVIS endpoints. The implementation is evidence-first: unavailable evidence must never be interpreted as low risk.

## Authentication

Authenticated endpoints require the same user session or token used by the live product. Some endpoints also require an active entitlement and an available output.

## POST /api/v1/unified/analyze

Runs unified analysis for a supported Solana target.

Request body:

```json
{
  "target": "So11111111111111111111111111111111111111112",
  "target_type": "token",
  "network": "solana-mainnet"
}
```

Accepted request fields:

- `input`
- `context`
- `target`
- `target_type`
- `target_id`
- `network`
- `notes`

Supported target type hints include `wallet`, `token`, `transaction`, `program`, and `project`.

Success responses use this envelope:

```json
{
  "success": true,
  "code": "OK",
  "message": "Analysis completed",
  "data": {
    "input_type": "token",
    "summary": "Evidence-backed summary",
    "sections": {},
    "security_radars": {},
    "sources": ["koschei_security_rules", "solana_rpc"],
    "partial_failures": []
  }
}
```

When live evidence is unavailable, the endpoint returns an explicit failure and does not charge an output:

```json
{
  "ok": false,
  "error": "real_data_unavailable",
  "charged": false,
  "sections": {}
}
```

## POST /api/v1/radar/check

Runs the ARVIS radar analysis arms and returns a signed final verdict only when the required evidence exists.

Request body:

```json
{
  "target": "So11111111111111111111111111111111111111112",
  "network": "solana-mainnet",
  "mode": "manual_dashboard_check"
}
```

`address` is accepted as an alias for `target`.

Success response shape:

```json
{
  "ok": true,
  "bundle": {},
  "arms": [],
  "final_verdict": {
    "signed": true
  }
}
```

If the evidence boundary is not satisfied, the response is unsigned and `charged` is `false`.

## GET /api/v1/risk/badge

The public badge route is registered in the server boot chain but is **readiness-gated and disabled by default**.

`KOSCHEI_PUBLIC_BADGE_ENABLED=true` is an explicit operator opt-in. Registration or opt-in alone is not a production-readiness claim. The current badge handler still consumes the legacy ARVIS compatibility final rather than the canonical unified decision path, so Koschei does not advertise a stable signed public badge contract yet.

With the default configuration, the runtime feature gate returns `503` with `code: feature_disabled` and `feature: public_badge`.

Do not publish cached grade, numeric risk-index, verdict or signature examples as if they were current public badge outputs. A future public badge may be enabled only after it is bound to the canonical deterministic decision/evidence contract and its low-cost public abuse boundary is verified.

## Status behavior

- `200` — evidence-backed success on a production-ready enabled route
- `400` — invalid input
- `401` — authentication required
- `402` — active entitlement or output required
- `502` — authenticated analysis could not obtain sufficient real evidence
- `503` — readiness/feature gate disabled or required public evidence unavailable

## Integration rule

Always check the evidence state and signed decision contract before displaying a verdict. Missing evidence is not a safety signal. A registered route is not, by itself, proof that the capability is production-ready.
