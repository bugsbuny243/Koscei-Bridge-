CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS plans (
  id text PRIMARY KEY,
  name text NOT NULL,
  price_try integer NOT NULL DEFAULT 0,
  monthly_credits integer NOT NULL DEFAULT 0,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

-- Cancel all complimentary free outputs. Paid entitlements are intentionally untouched.
UPDATE entitlements
SET outputs_total = 0,
    outputs_remaining = 0,
    updated_at = now()
WHERE COALESCE(plan_id, 'free') = 'free'
  AND status = 'active';

UPDATE plans
SET monthly_credits = 0,
    updated_at = now()
WHERE id = 'free';
