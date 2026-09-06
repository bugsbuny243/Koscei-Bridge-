UPDATE arvis_stream_processing
SET status = 'exhausted',
    updated_at = now()
WHERE status = 'failed'
  AND attempts >= 3;

CREATE OR REPLACE FUNCTION normalize_arvis_processing_status()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.status = 'failed' AND COALESCE(NEW.attempts, 0) >= 3 THEN
        NEW.status := 'exhausted';
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS arvis_processing_status_normalizer ON arvis_stream_processing;
CREATE TRIGGER arvis_processing_status_normalizer
BEFORE INSERT OR UPDATE OF status, attempts
ON arvis_stream_processing
FOR EACH ROW
EXECUTE FUNCTION normalize_arvis_processing_status();

CREATE INDEX IF NOT EXISTS arvis_stream_processing_exhausted_idx
ON arvis_stream_processing (status, updated_at DESC)
WHERE status = 'exhausted';
