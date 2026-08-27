ALTER TABLE tradepi_agent_followups
    DROP CONSTRAINT IF EXISTS tradepi_agent_followups_status_check;

ALTER TABLE tradepi_agent_followups
    ADD CONSTRAINT tradepi_agent_followups_status_check
    CHECK (status IN ('pending','processing','sent','cancelled','failed'));

UPDATE tradepi_agent_followups
SET status='pending', updated_at=NOW(), last_error=CASE
    WHEN last_error='' THEN 'recovered stale processing claim during migration'
    ELSE last_error
END
WHERE status='processing';

CREATE INDEX IF NOT EXISTS tradepi_agent_followups_processing_idx
    ON tradepi_agent_followups (updated_at, id)
    WHERE status='processing';
