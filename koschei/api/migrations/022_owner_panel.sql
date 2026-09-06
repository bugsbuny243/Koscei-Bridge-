CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS payment_requests (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid()
);

-- Owner Panel hardening and operational tables.
-- Owner authorization is derived from OWNER_WALLET + OWNER_SECRET, not a DB role.

ALTER TABLE app_user_profiles
    ADD COLUMN IF NOT EXISTS wallet_address TEXT,
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS banned_at TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS ban_reason TEXT;

DROP INDEX IF EXISTS idx_app_user_profiles_role;
ALTER TABLE app_user_profiles DROP COLUMN IF EXISTS role;

CREATE INDEX IF NOT EXISTS idx_app_user_profiles_wallet_address
    ON app_user_profiles (lower(wallet_address));
CREATE INDEX IF NOT EXISTS idx_app_user_profiles_status
    ON app_user_profiles (status);

ALTER TABLE payment_requests
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'pending',
    ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;

DO $$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'payment_requests_status_check') THEN
        ALTER TABLE payment_requests
            ADD CONSTRAINT payment_requests_status_check CHECK (status IN ('pending','approved','rejected'));
    END IF;
END $$;

CREATE TABLE IF NOT EXISTS credit_events (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email TEXT,
    amount INTEGER NOT NULL,
    reason TEXT,
    event_type TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS ai_command_logs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    command TEXT NOT NULL,
    output TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'queued',
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS ai_command_logs_created_at_idx ON ai_command_logs (created_at DESC);

CREATE TABLE IF NOT EXISTS system_analytics (
    day DATE PRIMARY KEY DEFAULT CURRENT_DATE,
    active_users INTEGER NOT NULL DEFAULT 0,
    revenue_try NUMERIC NOT NULL DEFAULT 0,
    credits_consumed INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
