CREATE TABLE IF NOT EXISTS defense_finding_publications (
    finding_ref text PRIMARY KEY REFERENCES defense_program_findings(finding_ref) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'draft',
    public_title text NOT NULL DEFAULT '',
    public_summary text NOT NULL DEFAULT '',
    redaction_profile text NOT NULL DEFAULT 'public-contract-finding-v1',
    published_at timestamptz,
    published_by text,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_finding_publications_status_check CHECK (status IN ('draft','public','hidden')),
    CONSTRAINT defense_finding_publications_redaction_check CHECK (redaction_profile = 'public-contract-finding-v1'),
    CONSTRAINT defense_finding_publications_title_length CHECK (char_length(public_title) <= 180),
    CONSTRAINT defense_finding_publications_summary_length CHECK (char_length(public_summary) <= 1200),
    CONSTRAINT defense_finding_publications_public_time CHECK (status <> 'public' OR published_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS defense_finding_publications_status_published_idx
    ON defense_finding_publications (status, published_at DESC)
    WHERE status = 'public';

CREATE TABLE IF NOT EXISTS defense_finding_publication_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_ref text NOT NULL REFERENCES defense_program_findings(finding_ref) ON DELETE RESTRICT,
    action text NOT NULL,
    actor text NOT NULL DEFAULT 'owner',
    publication_state jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_finding_publication_events_action_check CHECK (action IN ('created','published','hidden','drafted','updated')),
    CONSTRAINT defense_finding_publication_events_state_object CHECK (jsonb_typeof(publication_state) = 'object'),
    CONSTRAINT defense_finding_publication_events_actor_nonempty CHECK (btrim(actor) <> '')
);

CREATE INDEX IF NOT EXISTS defense_finding_publication_events_ref_created_idx
    ON defense_finding_publication_events (finding_ref, created_at DESC);

CREATE OR REPLACE FUNCTION validate_defense_finding_publication()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    finding_severity text;
    finding_confidence text;
    finding_lifecycle text;
    artifact_trust text;
BEGIN
    IF NEW.status <> 'public' THEN
        RETURN NEW;
    END IF;

    SELECT f.severity, f.confidence, f.lifecycle_status, a.trust_level
      INTO finding_severity, finding_confidence, finding_lifecycle, artifact_trust
      FROM defense_program_findings f
      LEFT JOIN defense_program_artifacts a ON a.artifact_ref = f.source_artifact_ref
     WHERE f.finding_ref = NEW.finding_ref;

    IF finding_severity IS NULL THEN
        RAISE EXCEPTION 'finding does not exist';
    END IF;
    IF finding_severity NOT IN ('high','critical') THEN
        RAISE EXCEPTION 'only high or critical findings can be public';
    END IF;
    IF finding_confidence = 'unverified' THEN
        RAISE EXCEPTION 'unverified findings cannot be public';
    END IF;
    IF finding_lifecycle = 'rejected' THEN
        RAISE EXCEPTION 'rejected findings cannot be public';
    END IF;
    IF artifact_trust IS NULL OR artifact_trust NOT IN ('observed','verified') THEN
        RAISE EXCEPTION 'finding source artifact is not publishable';
    END IF;
    IF btrim(NEW.public_title) = '' OR btrim(NEW.public_summary) = '' THEN
        RAISE EXCEPTION 'public finding title and summary are required';
    END IF;

    NEW.published_at = COALESCE(NEW.published_at, now());
    NEW.published_by = COALESCE(NULLIF(btrim(NEW.published_by),''), 'owner');
    NEW.updated_at = now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS defense_finding_publications_validate ON defense_finding_publications;
CREATE TRIGGER defense_finding_publications_validate
BEFORE INSERT OR UPDATE ON defense_finding_publications
FOR EACH ROW EXECUTE FUNCTION validate_defense_finding_publication();

DROP TRIGGER IF EXISTS defense_finding_publication_events_immutable ON defense_finding_publication_events;
CREATE TRIGGER defense_finding_publication_events_immutable
BEFORE UPDATE OR DELETE ON defense_finding_publication_events
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
