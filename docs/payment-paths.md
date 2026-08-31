# Koschei payment path

## Supported billing boundary

Koschei Web3 keeps billing and product authorization separate. **Starter**, **Professional**, and **Enterprise** access is granted only through an active server-side entitlement.

The repository does not expose a browser-controlled price or a client-side entitlement activation path. Payment-provider data is treated as external evidence for an entitlement decision, not as authority supplied by the frontend.

## Supported provider records

Current entitlement activation accepts the existing `shopier`, `shopier_manual`, and `owner_manual` provider records. Provider-specific secrets remain server-side and must never be embedded in the frontend bundle or committed to the repository.

Any provider identifier outside that explicit allowlist is rejected. It must never be silently normalized to an owner/manual path, because payment evidence is not authorization authority.

## Authorization flow

1. A customer has an authenticated Koschei account.
2. A supported server-side billing or owner workflow records the payment/approval evidence.
3. The backend validates the canonical plan identifier and provider record.
4. The backend activates or updates the customer's entitlement.
5. Premium access is derived only from an active, non-expired entitlement.
6. If billing evidence or entitlement state is unavailable, paid access remains unavailable.

The frontend never controls plan authority, output capacity, entitlement status, or provider verification.

## Canonical paid plans

| Plan | Canonical ID | Current output capacity |
| --- | --- | ---: |
| Starter | `starter` | 25 |
| Professional | `professional` | 100 |
| Enterprise | `enterprise` | 300 |

These capacities describe the current entitlement implementation. Product pages must not describe unfinished security modules as production-ready merely because a plan exists.

## Historical records

Existing databases may contain records from retired billing experiments. Historical records may remain for audit and migration integrity, but retired providers are not accepted for new entitlement activation and are not part of the supported runtime contract.
