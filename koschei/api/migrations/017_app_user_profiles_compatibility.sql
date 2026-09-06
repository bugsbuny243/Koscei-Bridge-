-- Migration: make legacy app_user_profiles tables compatible with customer auth provisioning
CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE app_user_profiles
    ADD COLUMN IF NOT EXISTS auth_subject TEXT;

ALTER TABLE app_user_profiles
    ADD COLUMN IF NOT EXISTS email TEXT;

ALTER TABLE app_user_profiles
    ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';

ALTER TABLE app_user_profiles
    ADD COLUMN IF NOT EXISTS plan_id TEXT NOT NULL DEFAULT 'free';

ALTER TABLE app_user_profiles
    ADD COLUMN IF NOT EXISTS credits INTEGER NOT NULL DEFAULT 0;

ALTER TABLE app_user_profiles
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();

ALTER TABLE app_user_profiles
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

UPDATE app_user_profiles
SET email = lower(email)
WHERE email IS NOT NULL;

UPDATE app_user_profiles
SET auth_subject = 'email:' || lower(email)
WHERE (auth_subject IS NULL OR trim(auth_subject) = '')
  AND email IS NOT NULL;

UPDATE app_user_profiles
SET role = 'user'
WHERE role IS NULL OR role = '' OR role IN ('admin', 'owner');

UPDATE app_user_profiles
SET plan_id = 'free'
WHERE plan_id IS NULL OR plan_id = '';

UPDATE app_user_profiles
SET credits = 0
WHERE credits IS NULL;

UPDATE app_user_profiles
SET created_at = now()
WHERE created_at IS NULL;

UPDATE app_user_profiles
SET updated_at = now()
WHERE updated_at IS NULL;

ALTER TABLE app_user_profiles
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

WITH duplicate_profiles AS (
    SELECT id,
           auth_subject,
           row_number() OVER (PARTITION BY auth_subject ORDER BY created_at, id) AS duplicate_rank
    FROM app_user_profiles
    WHERE auth_subject IS NOT NULL
      AND trim(auth_subject) <> ''
)
UPDATE app_user_profiles p
SET auth_subject = duplicate_profiles.auth_subject || ':duplicate:' || p.id::text,
    updated_at = now()
FROM duplicate_profiles
WHERE p.id = duplicate_profiles.id
  AND duplicate_profiles.duplicate_rank > 1;

CREATE UNIQUE INDEX IF NOT EXISTS idx_app_user_profiles_auth_subject_unique
ON app_user_profiles(auth_subject);

CREATE INDEX IF NOT EXISTS idx_app_user_profiles_email ON app_user_profiles(lower(email));
CREATE INDEX IF NOT EXISTS idx_app_user_profiles_role ON app_user_profiles(role);
