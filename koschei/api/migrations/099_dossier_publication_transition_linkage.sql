-- Bind every new dossier publication state transition to exactly one immutable
-- audit event. Existing rows predate this linkage and are intentionally left
-- unvalidated. PostgreSQL owns transition IDs and canonicalizes the event
-- snapshot, so application callers cannot forget or reuse the ledger identity.

ALTER TABLE dossier_publications
    ADD COLUMN IF NOT EXISTS transition_id uuid;

ALTER TABLE dossier_publication_events
    ADD COLUMN IF NOT EXISTS transition_id uuid;

CREATE UNIQUE INDEX IF NOT EXISTS dossier_publications_transition_unique_idx
    ON dossier_publications (transition_id)
    WHERE transition_id IS NOT NULL;

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

-- Every publication INSERT/UPDATE receives a fresh database-owned transition ID.
-- Client supplied IDs are deliberately ignored, preventing transition replay.
CREATE OR REPLACE FUNCTION prepare_dossier_publication_transition()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.transition_id := gen_random_uuid();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS dossier_publications_prepare_transition ON dossier_publications;
CREATE TRIGGER dossier_publications_prepare_transition
BEFORE INSERT OR UPDATE ON dossier_publications
FOR EACH ROW
EXECUTE FUNCTION prepare_dossier_publication_transition();

-- The application already writes an immutable audit event in the same
-- transaction. PostgreSQL attaches the current transition ID and overwrites the
-- state-bearing audit fields with the authoritative publication row. This keeps
-- the event useful even if an application caller supplied stale display fields.
CREATE OR REPLACE FUNCTION prepare_dossier_publication_event_link()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    publication dossier_publications%ROWTYPE;
    expected_actor text;
BEGIN
    SELECT * INTO publication
    FROM dossier_publications
    WHERE case_ref = NEW.case_ref;

    IF NOT FOUND OR publication.transition_id IS NULL THEN
        RAISE EXCEPTION 'dossier publication event has no active state transition';
    END IF;

    expected_actor := CASE publication.published_by
        WHEN 'owner' THEN 'owner'
        WHEN 'koschei-autopublish/v1' THEN 'autopublish'
        ELSE NULL
    END;
    IF expected_actor IS NULL OR NEW.actor <> expected_actor THEN
        RAISE EXCEPTION 'dossier publication event actor does not match publisher';
    END IF;

    -- Older owner code can describe a first hidden state as "hidden" even though
    -- the durable audit vocabulary is "hide". Normalize before the table CHECK.
    IF NEW.action = 'hidden' THEN
        NEW.action := 'hide';
    END IF;

    NEW.transition_id := publication.transition_id;
    NEW.publication_state := COALESCE(NEW.publication_state, '{}'::jsonb) || jsonb_build_object(
        'status', publication.status,
        'featured', publication.featured,
        'public_title', publication.public_title,
        'public_summary', publication.public_summary,
        'redaction_profile', publication.redaction_profile,
        'published_by', publication.published_by
    );
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS dossier_publication_events_prepare_link ON dossier_publication_events;
CREATE TRIGGER dossier_publication_events_prepare_link
BEFORE INSERT ON dossier_publication_events
FOR EACH ROW
EXECUTE FUNCTION prepare_dossier_publication_event_link();

-- Commit-time verification sees both the publication mutation and the event
-- insert from the transaction. It rejects direct SQL or application bugs that
-- mutate visibility without the matching immutable event.
CREATE OR REPLACE FUNCTION enforce_dossier_publication_transition_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    expected_actor text;
    expected_action text;
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

    IF TG_OP = 'INSERT' THEN
        expected_action := CASE NEW.status
            WHEN 'public' THEN 'publish'
            WHEN 'hidden' THEN 'hide'
            ELSE 'draft'
        END;
    ELSIF OLD.status IS DISTINCT FROM NEW.status THEN
        expected_action := CASE NEW.status
            WHEN 'public' THEN 'publish'
            WHEN 'hidden' THEN 'hide'
            ELSE 'draft'
        END;
    ELSIF OLD.featured IS DISTINCT FROM NEW.featured THEN
        expected_action := CASE WHEN NEW.featured THEN 'feature' ELSE 'unfeature' END;
    ELSE
        expected_action := 'update';
    END IF;

    SELECT EXISTS (
        SELECT 1
        FROM dossier_publication_events e
        WHERE e.transition_id = NEW.transition_id
          AND e.case_ref = NEW.case_ref
          AND e.actor = expected_actor
          AND e.action = expected_action
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
