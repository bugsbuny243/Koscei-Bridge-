-- Drop unique constraint on email, keep unique on auth_subject
ALTER TABLE app_user_profiles
DROP CONSTRAINT IF EXISTS app_user_profiles_email_key;

ALTER TABLE app_user_profiles
DROP CONSTRAINT IF EXISTS app_user_profiles_email_unique;

DROP INDEX IF EXISTS idx_app_user_profiles_email_unique;
