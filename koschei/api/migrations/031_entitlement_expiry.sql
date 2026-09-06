ALTER TABLE entitlements
    ADD COLUMN IF NOT EXISTS expires_at TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_entitlements_email_status_expires
    ON entitlements (lower(email), status, expires_at);
