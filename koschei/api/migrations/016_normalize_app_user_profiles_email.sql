-- Normalize legacy app_user_profiles email data before safe auth profile syncs.
-- This migration is intentionally defensive: it can run before or after older
-- hardening migrations and avoids failing when case-insensitive duplicates from
-- previous Railway/Neon auth setups are present.
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

ALTER TABLE app_user_profiles
    ADD COLUMN IF NOT EXISTS auth_subject TEXT,
    ADD COLUMN IF NOT EXISTS email TEXT,
    ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS plan_id TEXT DEFAULT 'free',
    ADD COLUMN IF NOT EXISTS credits INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now(),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();

UPDATE app_user_profiles
SET email = trim(email)
WHERE email IS NOT NULL
  AND email <> trim(email);

UPDATE app_user_profiles
SET email = 'profile-' || id::text || '@local.invalid',
    updated_at = now()
WHERE email IS NULL OR trim(email) = '';

-- Keep the newest row for each normalized email. Older rows are retained for
-- audit/history but moved to deterministic local.invalid aliases so lowercasing
-- the canonical row cannot violate app_user_profiles_email_key.
WITH ranked_emails AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY lower(trim(email))
               ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST, id DESC
           ) AS duplicate_rank
    FROM app_user_profiles
    WHERE email IS NOT NULL AND trim(email) <> ''
)
UPDATE app_user_profiles p
SET email = 'profile-' || p.id::text || '+duplicate@local.invalid',
    updated_at = now()
FROM ranked_emails r
WHERE p.id = r.id
  AND r.duplicate_rank > 1;

UPDATE app_user_profiles
SET email = lower(trim(email)),
    updated_at = now()
WHERE email IS NOT NULL
  AND email <> lower(trim(email));

-- If old data contained duplicate auth_subject values because a unique index was
-- missing, keep the newest subject owner and clear stale rows before indexing.
WITH ranked_subjects AS (
    SELECT id,
           row_number() OVER (
               PARTITION BY auth_subject
               ORDER BY updated_at DESC NULLS LAST, created_at DESC NULLS LAST, id DESC
           ) AS duplicate_rank
    FROM app_user_profiles
    WHERE auth_subject IS NOT NULL AND trim(auth_subject) <> ''
)
UPDATE app_user_profiles p
SET auth_subject = NULL,
    updated_at = now()
FROM ranked_subjects r
WHERE p.id = r.id
  AND r.duplicate_rank > 1;

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

CREATE INDEX IF NOT EXISTS idx_app_user_profiles_lower_email ON app_user_profiles (lower(email));
CREATE INDEX IF NOT EXISTS idx_app_user_profiles_auth_subject ON app_user_profiles (auth_subject);
