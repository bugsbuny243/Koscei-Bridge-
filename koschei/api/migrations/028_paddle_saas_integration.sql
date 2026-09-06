CREATE TABLE IF NOT EXISTS paddle_customers (
    id SERIAL PRIMARY KEY,
    paddle_customer_id VARCHAR(255) UNIQUE NOT NULL,
    email VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS paddle_subscriptions (
    id SERIAL PRIMARY KEY,
    paddle_subscription_id VARCHAR(255) UNIQUE NOT NULL,
    customer_id INTEGER REFERENCES paddle_customers(id),
    product_id VARCHAR(255) NOT NULL,
    plan_tier VARCHAR(50) NOT NULL,
    status VARCHAR(50) DEFAULT 'active',
    current_period_end TIMESTAMP,
    cancel_at_period_end BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_paddle_customers_email ON paddle_customers (email);
CREATE INDEX IF NOT EXISTS idx_paddle_subscriptions_customer_id ON paddle_subscriptions (customer_id);
CREATE INDEX IF NOT EXISTS idx_paddle_subscriptions_status_period ON paddle_subscriptions (status, current_period_end);

CREATE TABLE IF NOT EXISTS b2b_api_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_subject TEXT NOT NULL,
    email TEXT NOT NULL,
    name TEXT NOT NULL,
    key_prefix TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    subscription_id INTEGER REFERENCES paddle_subscriptions(id),
    rate_limit_per_minute INTEGER DEFAULT 100,
    monthly_quota INTEGER DEFAULT 1000,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NULL,
    revoked_at TIMESTAMPTZ NULL
);

ALTER TABLE b2b_api_keys ADD COLUMN IF NOT EXISTS subscription_id INTEGER REFERENCES paddle_subscriptions(id);
ALTER TABLE b2b_api_keys ADD COLUMN IF NOT EXISTS rate_limit_per_minute INTEGER DEFAULT 100;
ALTER TABLE b2b_api_keys ADD COLUMN IF NOT EXISTS monthly_quota INTEGER DEFAULT 1000;

ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS subscription_id INTEGER REFERENCES paddle_subscriptions(id);
ALTER TABLE api_keys ADD COLUMN IF NOT EXISTS monthly_quota INTEGER DEFAULT 1000;
UPDATE api_keys SET monthly_quota = COALESCE(monthly_quota, monthly_limit, 1000);

CREATE INDEX IF NOT EXISTS idx_b2b_api_keys_subscription_id ON b2b_api_keys (subscription_id);
CREATE INDEX IF NOT EXISTS idx_api_keys_subscription_id ON api_keys (subscription_id);
