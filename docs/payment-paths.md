# Koschei payment paths

## Active payment path: Paddle

Paddle is the active SaaS payment provider for the canonical paid plans: **Starter**, **Professional**, and **Enterprise**. KOSCH holdings are not a billing entitlement.

### Canonical Paddle production catalog

Create exactly these three recurring subscription products/prices in Paddle before enabling checkout:

| Koschei plan | Paddle product name | Billing cadence | USD price | Required server price ID |
| --- | --- | --- | ---: | --- |
| `starter` | Koschei Starter | Monthly recurring | $299 | `PADDLE_STARTER_PRICE_ID` |
| `professional` | Koschei Professional | Monthly recurring | $999 | `PADDLE_PROFESSIONAL_PRICE_ID` |
| `enterprise` | Koschei Enterprise | Monthly recurring | $4,999 | `PADDLE_ENTERPRISE_PRICE_ID` |

Optional product IDs may also be configured as `PADDLE_STARTER_PRODUCT_ID`, `PADDLE_PROFESSIONAL_PRODUCT_ID`, and `PADDLE_ENTERPRISE_PRODUCT_ID`, but the checkout path is authorized by the server-side **price IDs**.

The public pricing page is an ARVIS early-access surface. The current production focus is wallet-address investigation. Higher-tier radar/developer routes can remain entitlement-gated while they complete production validation; the catalog must not describe unfinished modules as already-complete production features.

### Required production configuration

Set these server-side values in the deployment environment:

```text
PADDLE_ENV=production
PADDLE_API_KEY=
PADDLE_CLIENT_TOKEN=
PADDLE_WEBHOOK_SECRET=
PADDLE_STARTER_PRICE_ID=
PADDLE_PROFESSIONAL_PRICE_ID=
PADDLE_ENTERPRISE_PRICE_ID=
PADDLE_STARTER_PRODUCT_ID=
PADDLE_PROFESSIONAL_PRODUCT_ID=
PADDLE_ENTERPRISE_PRODUCT_ID=
PUBLIC_APP_URL=https://tradepigloball.co
PADDLE_CHECKOUT_URL=https://tradepigloball.co/paddle-checkout
```

The Paddle notification destination is:

```text
https://tradepigloball.co/api/paddle/webhook
```

The billing service currently processes `transaction.completed`. The webhook secret must match that notification destination.

### Readiness gate

`GET /paddle/public-config` is the browser-safe readiness source. Checkout must remain fail-closed until it reports all three canonical plans ready.

Expected production conditions:

- `paddle.checkout_ready = true`
- `paddle.automation_ready = true`
- `paddle.all_plans_ready = true`
- `paddle.configured_plan_count = 3`
- `paddle.starter_ready = true`
- `paddle.professional_ready = true`
- `paddle.enterprise_ready = true`

If Paddle has no active subscription prices or the deployment has no matching price IDs, the pricing page deliberately blocks purchase actions instead of pretending checkout is live.

Paddle account/domain approval is provider-side state and cannot be repaired by repository code. The public site must keep Terms, Privacy, and Refund Policy reachable while Paddle reviews the domain/account.

### Transaction flow

1. An authenticated customer selects Starter, Professional, or Enterprise.
2. The browser first reads `/paddle/public-config`; an unready plan remains blocked.
3. The customer calls `POST /api/paddle/checkout` or `POST /api/v1/paddle/checkout` with only the selected canonical plan.
4. The backend maps the plan to the configured Paddle price ID and creates the Paddle transaction. The frontend never sends or controls the price.
5. Paddle sends a signed webhook to `/api/paddle/webhook`.
6. The backend verifies `PADDLE_WEBHOOK_SECRET`, binds the transaction to the authenticated Koschei account and expected price ID, and records the provider event idempotently.
7. A valid completed transaction activates or updates the customer's entitlement.
8. Customer premium access is read from active, non-expired `entitlements`; no active entitlement means no premium analysis.

## Legacy payment path: Shopier / payment_requests

`payment_requests` is retained for legacy Shopier/manual review flows and owner panel visibility. It is not the canonical SaaS checkout path.

1. Legacy payment requests may still exist where explicitly enabled.
2. Owner approval can activate an entitlement through the existing manual review path.
3. Historical records are retained rather than destructively migrated.
4. New Starter / Professional / Enterprise sales should use Paddle and `orders` + `entitlements`.
