-- Polar SaaS billing edge.
-- Raw webhook payloads are intentionally not retained. The ledger stores only
-- the provider event identity, binding evidence and a SHA-256 payload digest.

CREATE UNIQUE INDEX IF NOT EXISTS entitlements_polar_external_payment_uidx
    ON entitlements (external_payment_id)
    WHERE payment_provider = 'polar'
      AND external_payment_id IS NOT NULL
      AND external_payment_id <> '';

CREATE TABLE IF NOT EXISTS billing_provider_events (
    provider text NOT NULL,
    event_id text NOT NULL,
    event_type text NOT NULL,
    external_subscription_id text,
    plan_id text,
    auth_subject text,
    email text,
    product_id text,
    raw_sha256 text NOT NULL CHECK (raw_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    occurred_at timestamptz,
    processed_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (provider, event_id),
    CONSTRAINT billing_provider_events_provider_check
        CHECK (provider <> ''),
    CONSTRAINT billing_provider_events_plan_check
        CHECK (plan_id IS NULL OR plan_id IN ('starter','professional','enterprise'))
);

CREATE INDEX IF NOT EXISTS billing_provider_events_subscription_idx
    ON billing_provider_events (provider, external_subscription_id, processed_at DESC)
    WHERE external_subscription_id IS NOT NULL;

COMMENT ON TABLE billing_provider_events IS
    'Provider-neutral idempotency/audit ledger for verified billing webhooks. Raw payment payloads are not stored.';
