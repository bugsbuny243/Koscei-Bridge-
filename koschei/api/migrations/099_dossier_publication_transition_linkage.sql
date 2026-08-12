-- Bind every new dossier publication state transition to exactly one immutable
-- audit event. Existing rows predate this linkage and are intentionally left
-- unvalidated; all new inserts/updates are fail-closed by NOT VALID checks plus
-- a deferred constraint trigger that runs at transaction commit.

ALTER TABLE dossier_publications
    ADD COLUMN IF NOT EXISTS transition_id uuid;

ALTER TABLE dossier_publication_events
    ADD COLUMN IF NOT EXISTS transition_id uuid;

CREATE UNIQUE INDEX IF NOT EXISTS dossier_publication_events_transition_unique_idx
    ON dossier_publication_events (transition_id)
    WHERE transition_id IS NOT NULL;

ALTER TABLE dossier_publications
    DROP CONSTRAINT IF EXISTS dossier_publications_transition_required;
ALTER TABLE dossier_publications
    ADD CONSTRAINT dossier_publications_transition_required
    CHECK (transition_id IS NOT NULL) NOT VALID;

ALTER TABLE dossier_publication_events
    DROP CONSTRAINT IF EXISTS dossier_publication_events_transition_required;
ALTER TABLE dossier_publication_events
    ADD CONSTRAINT dossier_publication_events_transition_required
    CHECK (transition_id IS NOT NULL) NOT VALID;

ALTER TABLE dossier_publications
    DROP CONSTRAINT IF EXISTS dossier_publications_publisher_contract;
ALTER TABLE dossier_publications
    ADD CONSTRAINT dossier_publications_publisher_contract
    CHECK (published_by IN ('owner','koschei-autopublish/v1')) NOT VALID;

ALTER TABLE dossier_publication_events
    DROP CONSTRAINT IF EXISTS dossier_publication_events_actor_contract;
ALTER TABLE dossier_publication_events
    ADD CONSTRAINT dossier_publication_events_actor_contract
    CHECK (actor IN ('owner','autopublish')) NOT VALID;

CREATE OR REPLACE FUNCTION enforce_dossier_publication_transition_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_actor text;
    event_matches boolean := false;
BEGIN
    IF NEW.transition_id IS NULL THEN
        RAISE EXCEPTION 'dossier publication transition_id is required';
    END IF;

    IF TG_OP = 'UPDATE' AND NEW.transition_id IS NOT DISTINCT FROM OLD.transition_id THEN
        RAISE EXCEPTION 'dossier publication updates require a fresh transition_id';
    END IF;

    expected_actor := CASE NEW.published_by
        WHEN 'owner' THEN 'owner'
        WHEN 'koschei-autopublish/v1' THEN 'autopublish'
        ELSE NULL
    END;
    IF expected_actor IS NULL THEN
        RAISE EXCEPTION 'dossier publication publisher is not authorized for the audit ledger';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM dossier_publication_events e
        WHERE e.transition_id = NEW.transition_id
          AND e.case_ref = NEW.case_ref
          AND e.actor = expected_actor
          AND e.publication_state->>'status' = NEW.status
          AND e.publication_state->>'published_by' = NEW.published_by
          AND e.publication_state->>'public_title' = NEW.public_title
          AND e.publication_state->>'public_summary' = NEW.public_summary
          AND e.publication_state->>'redaction_profile' = NEW.redaction_profile
          AND e.publication_state->>'featured' = CASE WHEN NEW.featured THEN 'true' ELSE 'false' END
    ) INTO event_matches;

    IF NOT event_matches THEN
        RAISE EXCEPTION 'dossier publication state is missing its matching immutable transition event';
    END IF;

    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS dossier_publications_transition_event_guard ON dossier_publications;
CREATE CONSTRAINT TRIGGER dossier_publications_transition_event_guard
AFTER INSERT OR UPDATE ON dossier_publications
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION enforce_dossier_publication_transition_event();
