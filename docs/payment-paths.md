# Koschei payment path

## Supported billing boundary

Koschei Web3 keeps billing and product authorization separate. **Starter**, **Professional**, and **Enterprise** access is granted only through an active server-side entitlement.

The repository does not expose a browser-controlled price or a client-side entitlement activation path. Payment-provider data is treated as external evidence for an entitlement decision, not as authority supplied by the frontend.

## Supported provider records

Polar is the active hosted billing edge for Koschei Web3. Existing `shopier`, `shopier_manual`, and `owner_manual` entitlement records remain supported for already-authorized/manual operations. Provider-specific tokens, webhook secrets and Polar product IDs remain server-side and must never be embedded in the frontend bundle or committed to the repository.

Any provider identifier outside the explicit allowlist is rejected. Retired Paddle evidence is not accepted for new activation and must never be silently normalized to an owner/manual path.

## Polar authorization flow

1. An authenticated customer requests checkout for a canonical Koschei plan.
2. The backend maps that plan to a server-configured Polar product ID and creates a hosted Polar checkout. The browser receives only the hosted checkout ID/URL.
3. Checkout creation or redirect success **does not grant product access**.
4. Polar sends a signed webhook to `/api/polar/webhook`.
5. The backend verifies the raw webhook body and signed delivery headers before parsing or trusting event data.
6. For `subscription.active`, the backend verifies the product-to-plan mapping and the authenticated-subject/email metadata binding, records an idempotent evidence digest, and activates the server-side entitlement.
7. `subscription.canceled` and `subscription.past_due` are recorded but do not immediately revoke Koschei access; Polar can keep paid-period/grace-period access alive in those states.
8. For `subscription.revoked`, only the entitlement carrying the exact `polar` provider plus subscription ID evidence is revoked. Other manual/provider grants are not touched, and the customer profile is recomputed from any remaining active entitlement.
9. Duplicate events are idempotent, and an older `subscription.active` event cannot re-enable access after a newer/equal recorded revocation.

The frontend never controls plan authority, output capacity, entitlement status, webhook verification or provider-to-plan mapping.

## Polar server configuration

The deployment supplies these values as secrets/configuration, not source code:

- `POLAR_ACCESS_TOKEN`
- `POLAR_WEBHOOK_SECRET`
- `POLAR_PRODUCT_STARTER_ID`
- `POLAR_PRODUCT_PROFESSIONAL_ID`
- `POLAR_PRODUCT_ENTERPRISE_ID`
- `POLAR_ENVIRONMENT` (`production` or `sandbox`)
- optional HTTPS-only `POLAR_SUCCESS_URL`
- optional HTTPS-only `POLAR_RETURN_URL`

No Polar public-config endpoint exists. A missing token, webhook secret, product mapping, unsupported environment, invalid redirect URL, unknown provider or mismatched customer/product evidence fails closed.

## Canonical paid plans

| Plan | Canonical ID | Current output capacity |
| --- | --- | ---: |
| Starter | `starter` | 25 |
| Professional | `professional` | 100 |
| Enterprise | `enterprise` | 300 |

These capacities describe the current entitlement implementation. Product pages must not describe unfinished security modules as production-ready merely because a plan exists.

## Evidence and retention

Verified billing webhook payloads are not stored verbatim. The provider-neutral billing ledger stores the provider/event identity, subscription/product/customer binding fields required for reconciliation, the event time, and a SHA-256 digest of the raw signed payload. This preserves idempotency and provenance without retaining the payment payload itself.

## Historical records

Existing databases may contain Paddle schema/history from retired billing experiments. Applied migrations and historical rows remain for audit and migration integrity, but Paddle is not an accepted runtime provider and has no active checkout, webhook, public-config or browser CSP surface.
