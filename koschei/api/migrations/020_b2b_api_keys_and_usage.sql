CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS api_keys (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_subject text NOT NULL,
    email text NOT NULL,
    name text NOT NULL,
    key_prefix text NOT NULL,
    key_hash text NOT NULL UNIQUE,
    status text NOT NULL DEFAULT 'active',
    monthly_limit integer NOT NULL DEFAULT 1000,
    rate_limit_per_minute integer NOT NULL DEFAULT 60,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_used_at timestamptz NULL,
    revoked_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_api_keys_auth_subject ON api_keys(auth_subject);
CREATE INDEX IF NOT EXISTS idx_api_keys_status_hash ON api_keys(status, key_hash);

CREATE TABLE IF NOT EXISTS api_usage_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id uuid NOT NULL REFERENCES api_keys(id),
    auth_subject text NOT NULL,
    email text NOT NULL,
    endpoint text NOT NULL,
    request_id uuid NOT NULL UNIQUE,
    credits_reserved integer NOT NULL DEFAULT 0,
    credits_charged integer NOT NULL DEFAULT 0,
    status text NOT NULL,
    error_code text NULL,
    latency_ms integer NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz NULL
);

CREATE INDEX IF NOT EXISTS idx_api_usage_api_key_created ON api_usage_events(api_key_id, created_at DESC);

CREATE TABLE IF NOT EXISTS api_credit_ledger (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id uuid NOT NULL REFERENCES api_keys(id),
    auth_subject text NOT NULL,
    email text NOT NULL,
    amount integer NOT NULL,
    event_type text NOT NULL,
    reason text NOT NULL,
    request_id uuid NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_api_credit_ledger_key_created ON api_credit_ledger(api_key_id, created_at DESC);
