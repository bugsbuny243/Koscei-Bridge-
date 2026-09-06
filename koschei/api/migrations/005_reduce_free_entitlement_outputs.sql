-- Cancel active free entitlement outputs so legacy free rows cannot unlock premium modules.
UPDATE entitlements
SET
  outputs_remaining = 0,
  outputs_total = 0,
  updated_at = now()
WHERE status = 'active'
  AND COALESCE(plan_id, 'free') = 'free'
  AND (outputs_total <> 0 OR outputs_remaining <> 0);
