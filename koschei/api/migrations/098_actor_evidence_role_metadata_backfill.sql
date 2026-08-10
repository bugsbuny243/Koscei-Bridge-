-- Restore canonical actor-role semantics for evidence inserted through the Go
-- ActorDefenseStore. Older insertions omitted actor_role and therefore accepted
-- the column default ('actor') before the normalizer could use metadata.actor_role.
--
-- This migration deliberately does not infer roles from wallet behavior. It only
-- copies an explicit role already present in Koschei's persisted evidence metadata.

CREATE OR REPLACE FUNCTION sync_security_actor_evidence_role_from_metadata()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    metadata_role text;
BEGIN
    metadata_role := btrim(COALESCE(NEW.metadata->>'actor_role',''));
    IF metadata_role <> '' AND (btrim(COALESCE(NEW.actor_role,'')) = '' OR NEW.actor_role = 'actor') THEN
        NEW.actor_role := metadata_role;
    END IF;
    IF btrim(COALESCE(NEW.actor_role,'')) = '' THEN
        NEW.actor_role := 'actor';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS zz_security_actor_evidence_role_from_metadata ON security_actor_evidence;
CREATE TRIGGER zz_security_actor_evidence_role_from_metadata
BEFORE INSERT OR UPDATE ON security_actor_evidence
FOR EACH ROW
EXECUTE FUNCTION sync_security_actor_evidence_role_from_metadata();

-- Backfill only rows where the generic default masked an explicit persisted role.
UPDATE security_actor_evidence
SET actor_role = btrim(metadata->>'actor_role'),
    updated_at = now()
WHERE actor_role = 'actor'
  AND btrim(COALESCE(metadata->>'actor_role','')) <> ''
  AND btrim(metadata->>'actor_role') <> 'actor';

CREATE INDEX IF NOT EXISTS idx_security_actor_evidence_role_counterpart
    ON security_actor_evidence (network,actor_role,counterpart_kind,counterpart_id,last_observed_at DESC);
