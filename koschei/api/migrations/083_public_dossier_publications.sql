-- Public SOC publication state is deliberately separate from immutable dossier data.
-- A dossier export is never public merely because it exists; an owner must explicitly
-- publish it. The canonical bundle remains immutable in dossier_exports.

CREATE TABLE IF NOT EXISTS dossier_publications (
    case_ref text PRIMARY KEY REFERENCES dossier_exports(case_ref) ON DELETE RESTRICT,
    status text NOT NULL DEFAULT 'draft',
    public_title text NOT NULL DEFAULT '',
    public_summary text NOT NULL DEFAULT '',
    featured boolean NOT NULL DEFAULT false,
    redaction_profile text NOT NULL DEFAULT 'public-onchain-v1',
    published_at timestamptz,
    published_by text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT dossier_publications_status_check CHECK (status IN ('draft','public','hidden')),
    CONSTRAINT dossier_publications_case_ref_format CHECK (case_ref ~ '^KD1-[a-z2-7]{32}$'),
    CONSTRAINT dossier_publications_redaction_profile_nonempty CHECK (btrim(redaction_profile) <> ''),
    CONSTRAINT dossier_publications_public_time_check CHECK (status <> 'public' OR published_at IS NOT NULL),
    CONSTRAINT dossier_publications_featured_public_check CHECK (NOT featured OR status = 'public')
);

CREATE INDEX IF NOT EXISTS dossier_publications_public_feed_idx
    ON dossier_publications (featured DESC, published_at DESC, case_ref)
    WHERE status = 'public';

CREATE TABLE IF NOT EXISTS dossier_publication_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_ref text NOT NULL REFERENCES dossier_exports(case_ref) ON DELETE RESTRICT,
    action text NOT NULL,
    actor text NOT NULL,
    publication_state jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT dossier_publication_events_action_check CHECK (action IN ('publish','hide','draft','update','feature','unfeature')),
    CONSTRAINT dossier_publication_events_nonempty_check CHECK (btrim(case_ref) <> '' AND btrim(actor) <> ''),
    CONSTRAINT dossier_publication_events_state_object_check CHECK (jsonb_typeof(publication_state) = 'object')
);

CREATE INDEX IF NOT EXISTS dossier_publication_events_case_time_idx
    ON dossier_publication_events (case_ref, created_at DESC);

CREATE OR REPLACE FUNCTION reject_dossier_publication_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'dossier publication audit events are immutable';
END;
$$;

DROP TRIGGER IF EXISTS dossier_publication_events_immutable ON dossier_publication_events;
CREATE TRIGGER dossier_publication_events_immutable
BEFORE UPDATE OR DELETE ON dossier_publication_events
FOR EACH ROW EXECUTE FUNCTION reject_dossier_publication_event_mutation();
