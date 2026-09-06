CREATE TABLE IF NOT EXISTS paddle_webhook_events (
    event_id TEXT PRIMARY KEY,
    event_type TEXT NOT NULL DEFAULT '',
    occurred_at TIMESTAMPTZ,
    status TEXT NOT NULL DEFAULT 'processing',
    attempts INTEGER NOT NULL DEFAULT 1,
    last_error TEXT NOT NULL DEFAULT '',
    payload JSONB NOT NULL DEFAULT '{}'::jsonb,
    processed_at TIMESTAMPTZ,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS paddle_webhook_events_status_updated_idx
ON paddle_webhook_events (status, updated_at DESC);

-- orders belongs to the optional legacy payment schema and is not present on
-- every fresh installation. Do not make Paddle webhook idempotency depend on
-- that unrelated legacy table.
DO $$
BEGIN
    IF to_regclass('public.orders') IS NOT NULL THEN
        CREATE INDEX IF NOT EXISTS orders_provider_status_created_idx
        ON orders (provider, status, created_at DESC);
    END IF;
END $$;
