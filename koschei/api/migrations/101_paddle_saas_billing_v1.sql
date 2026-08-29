-- Wave 34: canonical subscription SaaS billing.
-- Webhook payloads are intentionally not retained; only a digest and provider
-- identifiers required for idempotency/audit are stored.

ALTER TABLE IF EXISTS entitlements
    ADD COLUMN IF NOT EXISTS payment_provider text;
ALTER TABLE IF EXISTS entitlements
    ADD COLUMN IF NOT EXISTS external_payment_id text;

CREATE UNIQUE INDEX IF NOT EXISTS entitlements_paddle_external_payment_uidx
    ON entitlements (external_payment_id)
    WHERE payment_provider = 'paddle'
      AND external_payment_id IS NOT NULL
      AND external_payment_id <> '';

CREATE TABLE IF NOT EXISTS paddle_billing_events (
    notification_id text PRIMARY KEY,
    event_type text NOT NULL,
    transaction_id text,
    plan_id text,
    auth_subject text,
    email text,
    raw_sha256 text NOT NULL CHECK (raw_sha256 ~ '^sha256:[0-9a-f]{64}$'),
    occurred_at timestamptz,
    processed_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT paddle_billing_events_plan_check
        CHECK (plan_id IS NULL OR plan_id IN ('starter','professional','enterprise'))
);

CREATE INDEX IF NOT EXISTS paddle_billing_events_transaction_idx
    ON paddle_billing_events (transaction_id, processed_at DESC)
    WHERE transaction_id IS NOT NULL;

COMMENT ON TABLE paddle_billing_events IS
    'Idempotency/audit ledger for verified Paddle webhooks. Raw payment payloads are not stored.';
