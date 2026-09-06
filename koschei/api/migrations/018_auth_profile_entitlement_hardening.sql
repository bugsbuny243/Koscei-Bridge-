-- Harden Neon Auth local provisioning tables for idempotent login/provision calls.
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS app_user_profiles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_subject TEXT UNIQUE,
    email TEXT UNIQUE NOT NULL,
    role TEXT NOT NULL DEFAULT 'user',
    plan_id TEXT NOT NULL DEFAULT 'free',
    credits INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS entitlements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    customer_id TEXT,
    email TEXT,
    plan_id TEXT,
    payment_request_id UUID,
    outputs_total INTEGER DEFAULT 0,
    outputs_remaining INTEGER DEFAULT 0,
    status TEXT DEFAULT 'active',
    created_at TIMESTAMPTZ DEFAULT now(),
    updated_at TIMESTAMPTZ DEFAULT now()
);

ALTER TABLE app_user_profiles
    ADD COLUMN IF NOT EXISTS auth_subject TEXT,
    ADD COLUMN IF NOT EXISTS email TEXT,
    ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS plan_id TEXT DEFAULT 'free',
    ADD COLUMN IF NOT EXISTS credits INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now(),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();

UPDATE app_user_profiles
SET email = lower(trim(email))
WHERE email IS NOT NULL;

UPDATE app_user_profiles
SET email = 'profile-' || id::text || '@local.invalid'
WHERE email IS NULL OR trim(email) = '';

WITH duplicate_emails AS (
    SELECT id,
           row_number() OVER (PARTITION BY lower(email) ORDER BY updated_at DESC, created_at DESC, id) AS duplicate_rank
    FROM app_user_profiles
)
UPDATE app_user_profiles p
SET email = regexp_replace(p.email, '@', '+duplicate-' || p.id::text || '@'),
    updated_at = now()
FROM duplicate_emails d
WHERE p.id = d.id
  AND d.duplicate_rank > 1;

WITH duplicate_subjects AS (
    SELECT id,
           row_number() OVER (PARTITION BY auth_subject ORDER BY updated_at DESC, created_at DESC, id) AS duplicate_rank
    FROM app_user_profiles
    WHERE auth_subject IS NOT NULL AND trim(auth_subject) <> ''
)
UPDATE app_user_profiles p
SET auth_subject = NULL,
    updated_at = now()
FROM duplicate_subjects d
WHERE p.id = d.id
  AND d.duplicate_rank > 1;

UPDATE app_user_profiles
SET role = 'user'
WHERE role IS NULL OR trim(role) = '';

UPDATE app_user_profiles
SET plan_id = 'free'
WHERE plan_id IS NULL OR trim(plan_id) = '';

UPDATE app_user_profiles SET credits = 0 WHERE credits IS NULL;
UPDATE app_user_profiles SET created_at = now() WHERE created_at IS NULL;
UPDATE app_user_profiles SET updated_at = now() WHERE updated_at IS NULL;

ALTER TABLE app_user_profiles
    ALTER COLUMN email SET NOT NULL,
    ALTER COLUMN role SET DEFAULT 'user',
    ALTER COLUMN role SET NOT NULL,
    ALTER COLUMN plan_id SET DEFAULT 'free',
    ALTER COLUMN plan_id SET NOT NULL,
    ALTER COLUMN credits SET DEFAULT 0,
    ALTER COLUMN credits SET NOT NULL,
    ALTER COLUMN created_at SET DEFAULT now(),
    ALTER COLUMN created_at SET NOT NULL,
    ALTER COLUMN updated_at SET DEFAULT now(),
    ALTER COLUMN updated_at SET NOT NULL;

DROP INDEX IF EXISTS idx_app_user_profiles_email;
CREATE UNIQUE INDEX IF NOT EXISTS idx_app_user_profiles_email_unique ON app_user_profiles(email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_app_user_profiles_auth_subject_unique ON app_user_profiles(auth_subject);
CREATE INDEX IF NOT EXISTS idx_app_user_profiles_role ON app_user_profiles(role);

ALTER TABLE entitlements
    ADD COLUMN IF NOT EXISTS customer_id TEXT,
    ADD COLUMN IF NOT EXISTS email TEXT,
    ADD COLUMN IF NOT EXISTS plan_id TEXT,
    ADD COLUMN IF NOT EXISTS payment_request_id UUID,
    ADD COLUMN IF NOT EXISTS outputs_total INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS outputs_remaining INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS status TEXT DEFAULT 'active',
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now(),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();

UPDATE entitlements SET email = lower(trim(email)) WHERE email IS NOT NULL;
UPDATE entitlements SET plan_id = 'free' WHERE plan_id IS NULL OR trim(plan_id) = '';
UPDATE entitlements SET outputs_total = 0 WHERE outputs_total IS NULL;
UPDATE entitlements SET outputs_remaining = 0 WHERE outputs_remaining IS NULL;
UPDATE entitlements SET status = 'active' WHERE status IS NULL OR trim(status) = '';
UPDATE entitlements SET created_at = now() WHERE created_at IS NULL;
UPDATE entitlements SET updated_at = now() WHERE updated_at IS NULL;

ALTER TABLE entitlements
    ALTER COLUMN outputs_total SET DEFAULT 0,
    ALTER COLUMN outputs_remaining SET DEFAULT 0,
    ALTER COLUMN status SET DEFAULT 'active',
    ALTER COLUMN created_at SET DEFAULT now(),
    ALTER COLUMN updated_at SET DEFAULT now();

WITH duplicate_free AS (
    SELECT id,
           row_number() OVER (PARTITION BY lower(email) ORDER BY outputs_remaining DESC, updated_at DESC, created_at DESC, id) AS duplicate_rank
    FROM entitlements
    WHERE email IS NOT NULL
      AND status = 'active'
      AND COALESCE(plan_id, 'free') = 'free'
)
UPDATE entitlements e
SET status = 'inactive',
    updated_at = now()
FROM duplicate_free d
WHERE e.id = d.id
  AND d.duplicate_rank > 1;

CREATE INDEX IF NOT EXISTS entitlements_email_idx ON entitlements (email);
CREATE INDEX IF NOT EXISTS entitlements_status_idx ON entitlements (status);
CREATE UNIQUE INDEX IF NOT EXISTS entitlements_one_active_free_per_email_idx
ON entitlements (lower(email))
WHERE status = 'active' AND COALESCE(plan_id, 'free') = 'free';
