-- Production hardening: Koschei is not a free tool.
-- Free profile records may exist for account display only, but they must never
-- grant runnable premium-module outputs.
UPDATE entitlements
SET outputs_total = 0,
    outputs_remaining = 0,
    updated_at = now()
WHERE status = 'active'
  AND COALESCE(plan_id, 'free') = 'free'
  AND (COALESCE(outputs_total, 0) <> 0 OR COALESCE(outputs_remaining, 0) <> 0);
