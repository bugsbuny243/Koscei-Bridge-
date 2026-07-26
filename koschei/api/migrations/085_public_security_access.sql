-- Public security evidence is not owner-exclusive. The principal that created
-- the dossier or program monitor controls visibility; owner access is reserved
-- for moderation, featuring and emergency hiding.

COMMENT ON TABLE dossier_publications IS
    'Mutable discovery state for immutable dossiers. Visibility may be controlled by the dossier creator (user, API account or owner).';
COMMENT ON COLUMN dossier_publications.published_by IS
    'Publisher principal such as user:<subject>, api_key:<id> or owner.';

CREATE INDEX IF NOT EXISTS dossier_exports_requester_case_idx
    ON dossier_exports (requested_by, case_ref);
CREATE INDEX IF NOT EXISTS dossier_publications_publisher_idx
    ON dossier_publications (published_by, updated_at DESC);

CREATE TABLE IF NOT EXISTS program_risk_publications (
    evidence_ref text PRIMARY KEY,
    status text NOT NULL DEFAULT 'draft',
    public_title text NOT NULL DEFAULT '',
    public_summary text NOT NULL DEFAULT '',
    published_by text NOT NULL,
    published_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT program_risk_publications_ref_check CHECK (evidence_ref ~ '^(KDS1|KDCE1)-[0-9a-f]{32}$'),
    CONSTRAINT program_risk_publications_status_check CHECK (status IN ('draft','public','hidden')),
    CONSTRAINT program_risk_publications_publisher_nonempty CHECK (btrim(published_by) <> ''),
    CONSTRAINT program_risk_publications_public_time_check CHECK (status <> 'public' OR published_at IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS program_risk_publications_feed_idx
    ON program_risk_publications (published_at DESC, evidence_ref)
    WHERE status='public';
CREATE INDEX IF NOT EXISTS program_risk_publications_publisher_idx
    ON program_risk_publications (published_by, updated_at DESC);

CREATE TABLE IF NOT EXISTS program_risk_publication_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    evidence_ref text NOT NULL,
    action text NOT NULL,
    actor text NOT NULL,
    publication_state jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT program_risk_publication_events_ref_check CHECK (evidence_ref ~ '^(KDS1|KDCE1)-[0-9a-f]{32}$'),
    CONSTRAINT program_risk_publication_events_action_check CHECK (action IN ('publish','hide','draft','update')),
    CONSTRAINT program_risk_publication_events_nonempty CHECK (btrim(actor) <> ''),
    CONSTRAINT program_risk_publication_events_state_object CHECK (jsonb_typeof(publication_state)='object')
);

CREATE INDEX IF NOT EXISTS program_risk_publication_events_ref_time_idx
    ON program_risk_publication_events (evidence_ref, created_at DESC);

CREATE OR REPLACE FUNCTION reject_program_risk_publication_event_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'program risk publication audit events are immutable';
END;
$$;

DROP TRIGGER IF EXISTS program_risk_publication_events_immutable ON program_risk_publication_events;
CREATE TRIGGER program_risk_publication_events_immutable
BEFORE UPDATE OR DELETE ON program_risk_publication_events
FOR EACH ROW EXECUTE FUNCTION reject_program_risk_publication_event_mutation();

CREATE INDEX IF NOT EXISTS defense_program_change_events_public_severity_idx
    ON defense_program_change_events (created_at DESC)
    WHERE severity IN ('high','critical');

CREATE TABLE IF NOT EXISTS defense_program_monitor_subscriptions (
    monitor_ref text NOT NULL REFERENCES defense_program_monitors(monitor_ref) ON DELETE RESTRICT,
    auth_subject text NOT NULL,
    active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (monitor_ref, auth_subject),
    CONSTRAINT defense_program_monitor_subscriptions_subject_nonempty CHECK (btrim(auth_subject) <> '')
);

CREATE INDEX IF NOT EXISTS defense_program_monitor_subscriptions_subject_idx
    ON defense_program_monitor_subscriptions (auth_subject, active, updated_at DESC);
CREATE INDEX IF NOT EXISTS defense_program_monitor_subscriptions_active_monitor_idx
    ON defense_program_monitor_subscriptions (monitor_ref)
    WHERE active=true;
