-- Migration: Neon Auth-backed customer profiles
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

-- Existing deployments may already have a legacy app_user_profiles table with
-- only a subset of the columns above. CREATE TABLE IF NOT EXISTS does not
-- backfill missing columns, so add them before creating indexes that depend on
-- those columns. Later hardening migrations normalize values and tighten
-- constraints once legacy data has been cleaned up.
ALTER TABLE app_user_profiles
    ADD COLUMN IF NOT EXISTS auth_subject TEXT,
    ADD COLUMN IF NOT EXISTS email TEXT,
    ADD COLUMN IF NOT EXISTS role TEXT DEFAULT 'user',
    ADD COLUMN IF NOT EXISTS plan_id TEXT DEFAULT 'free',
    ADD COLUMN IF NOT EXISTS credits INTEGER DEFAULT 0,
    ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ DEFAULT now(),
    ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ DEFAULT now();

CREATE INDEX IF NOT EXISTS idx_app_user_profiles_email ON app_user_profiles(lower(email));
CREATE INDEX IF NOT EXISTS idx_app_user_profiles_role ON app_user_profiles(role);
