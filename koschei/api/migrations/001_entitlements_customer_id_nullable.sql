CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS entitlements (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  customer_id text,
  email text,
  plan_id text,
  payment_request_id uuid,
  outputs_total int DEFAULT 0,
  outputs_remaining int DEFAULT 0,
  status text DEFAULT 'active',
  created_at timestamptz DEFAULT now(),
  updated_at timestamptz DEFAULT now()
);

ALTER TABLE entitlements
  ADD COLUMN IF NOT EXISTS customer_id text,
  ADD COLUMN IF NOT EXISTS email text,
  ADD COLUMN IF NOT EXISTS plan_id text,
  ADD COLUMN IF NOT EXISTS payment_request_id uuid,
  ADD COLUMN IF NOT EXISTS outputs_total int DEFAULT 0,
  ADD COLUMN IF NOT EXISTS outputs_remaining int DEFAULT 0,
  ADD COLUMN IF NOT EXISTS status text DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS created_at timestamptz DEFAULT now(),
  ADD COLUMN IF NOT EXISTS updated_at timestamptz DEFAULT now();

ALTER TABLE entitlements
  ALTER COLUMN customer_id DROP NOT NULL,
  ALTER COLUMN outputs_total SET DEFAULT 0,
  ALTER COLUMN outputs_remaining SET DEFAULT 0,
  ALTER COLUMN status SET DEFAULT 'active',
  ALTER COLUMN created_at SET DEFAULT now(),
  ALTER COLUMN updated_at SET DEFAULT now();

CREATE INDEX IF NOT EXISTS entitlements_email_idx ON entitlements (email);
CREATE INDEX IF NOT EXISTS entitlements_status_idx ON entitlements (status);
