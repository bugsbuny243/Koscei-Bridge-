-- Publication time is authorization state, not artifact time.
-- For transitions processed under this contract, published_at means the start
-- of the most recent/current public exposure interval. Hiding preserves that
-- historical interval start; republishing starts a new interval.

CREATE OR REPLACE FUNCTION prepare_dossier_publication_effective_time()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF TG_OP = 'INSERT' THEN
        IF NEW.status = 'public' THEN
            NEW.published_at := now();
        ELSE
            NEW.published_at := NULL;
        END IF;
        RETURN NEW;
    END IF;

    IF OLD.status IS DISTINCT FROM NEW.status AND NEW.status = 'public' THEN
        NEW.published_at := now();
    ELSE
        NEW.published_at := OLD.published_at;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS dossier_publications_effective_time_contract ON dossier_publications;
CREATE TRIGGER dossier_publications_effective_time_contract
BEFORE INSERT OR UPDATE ON dossier_publications
FOR EACH ROW
EXECUTE FUNCTION prepare_dossier_publication_effective_time();

-- The event timestamp is part of the public-exposure proof. Ignore caller
-- supplied created_at values and stamp a contract marker after Wave 28's event
-- linkage trigger has canonicalized the publication snapshot.
CREATE OR REPLACE FUNCTION prepare_dossier_publication_event_time_contract()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    NEW.created_at := now();
    NEW.publication_state := COALESCE(NEW.publication_state, '{}'::jsonb)
        || jsonb_build_object('publication_time_contract', 'db-owned-v1');
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS dossier_publication_events_time_contract ON dossier_publication_events;
CREATE TRIGGER dossier_publication_events_time_contract
BEFORE INSERT ON dossier_publication_events
FOR EACH ROW
EXECUTE FUNCTION prepare_dossier_publication_event_time_contract();

COMMENT ON COLUMN dossier_publications.published_at IS
    'For publication-time-v1 transitions: start of the most recent/current public exposure interval; preserved while non-public until the next publish transition.';
