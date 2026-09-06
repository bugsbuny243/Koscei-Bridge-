-- Legacy billing cleanup must be safe on both historical databases and fresh
-- installations where optional payment-provider columns/tables never existed.
DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='entitlements' AND column_name='payment_provider'
    ) THEN
        DELETE FROM entitlements WHERE lower(COALESCE(payment_provider, '')) = 'paddle';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='orders' AND column_name='provider'
    ) THEN
        DELETE FROM orders WHERE lower(COALESCE(provider, '')) = 'paddle';
    END IF;

    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='payment_requests' AND column_name='payment_provider'
    ) THEN
        DELETE FROM payment_requests WHERE lower(COALESCE(payment_provider, '')) = 'paddle';
    END IF;
END $$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='orders' AND column_name='provider'
    ) THEN
        ALTER TABLE orders ALTER COLUMN provider SET DEFAULT 'shopier';
    END IF;
    IF EXISTS (
        SELECT 1 FROM information_schema.columns
        WHERE table_schema='public' AND table_name='orders' AND column_name='currency'
    ) THEN
        ALTER TABLE orders ALTER COLUMN currency SET DEFAULT 'TRY';
    END IF;
END $$;

ALTER TABLE IF EXISTS api_keys DROP COLUMN IF EXISTS subscription_id;
ALTER TABLE IF EXISTS b2b_api_keys DROP COLUMN IF EXISTS subscription_id;

DROP TABLE IF EXISTS paddle_webhook_events;
DROP TABLE IF EXISTS paddle_subscriptions;
DROP TABLE IF EXISTS paddle_customers;
