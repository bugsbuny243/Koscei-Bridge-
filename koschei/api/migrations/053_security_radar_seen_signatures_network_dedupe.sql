-- Keep one network-aware dedupe key for Security Radar signatures.
-- Older production schemas may still have a legacy UNIQUE(module_id, signature)
-- constraint/index, which conflicts before MarkSignatureSeen's network-aware
-- ON CONFLICT clause can treat a repeated PumpPortal event as an ordinary no-op.

DO $$
DECLARE
  constraint_row RECORD;
BEGIN
  IF to_regclass('public.security_radar_seen_signatures') IS NULL THEN
    RETURN;
  END IF;

  FOR constraint_row IN
    SELECT c.conname
    FROM pg_constraint c
    JOIN pg_class t ON t.oid = c.conrelid
    JOIN pg_namespace n ON n.oid = t.relnamespace
    WHERE n.nspname = 'public'
      AND t.relname = 'security_radar_seen_signatures'
      AND c.contype = 'u'
      AND regexp_replace(pg_get_constraintdef(c.oid), '\s+', ' ', 'g') IN (
        'UNIQUE (module_id, signature)',
        'UNIQUE (signature, module_id)'
      )
  LOOP
    EXECUTE format(
      'ALTER TABLE public.security_radar_seen_signatures DROP CONSTRAINT %I',
      constraint_row.conname
    );
  END LOOP;
END $$;

DROP INDEX IF EXISTS public.security_radar_seen_signatures_legacy_unique_idx;

CREATE UNIQUE INDEX IF NOT EXISTS security_radar_seen_signatures_unique_idx
  ON public.security_radar_seen_signatures (signature, module_id, network);
