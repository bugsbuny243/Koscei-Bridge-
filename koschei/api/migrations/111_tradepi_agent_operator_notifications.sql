CREATE TABLE IF NOT EXISTS tradepi_agent_operator_notifications (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    escalation_id bigint NOT NULL REFERENCES tradepi_agent_escalations(id) ON DELETE CASCADE,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processing','delivered','cancelled','failed')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    UNIQUE (escalation_id)
);

CREATE INDEX IF NOT EXISTS tradepi_agent_operator_notifications_pending_idx
    ON tradepi_agent_operator_notifications (next_attempt_at, id)
    WHERE status='pending';

CREATE OR REPLACE FUNCTION tradepi_agent_enqueue_operator_notification()
RETURNS trigger AS $$
BEGIN
    IF NEW.status='open' THEN
        INSERT INTO tradepi_agent_operator_notifications (tenant_id, escalation_id, status, next_attempt_at)
        VALUES (NEW.tenant_id, NEW.id, 'pending', now())
        ON CONFLICT (escalation_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tradepi_agent_escalation_notification_trg ON tradepi_agent_escalations;
CREATE TRIGGER tradepi_agent_escalation_notification_trg
AFTER INSERT ON tradepi_agent_escalations
FOR EACH ROW EXECUTE FUNCTION tradepi_agent_enqueue_operator_notification();

CREATE OR REPLACE FUNCTION tradepi_agent_resolve_escalation_on_assignment()
RETURNS trigger AS $$
BEGIN
    IF COALESCE(OLD.owner_id,'')='' AND COALESCE(NEW.owner_id,'')<>'' THEN
        UPDATE tradepi_agent_escalations
        SET status='resolved', resolved_at=COALESCE(resolved_at, now())
        WHERE tenant_id=NEW.tenant_id
          AND channel=NEW.channel
          AND external_id=NEW.external_id
          AND status IN ('open','acknowledged');

        UPDATE tradepi_agent_operator_notifications n
        SET status='cancelled', updated_at=now(), last_error='lead assigned before operator notification delivery'
        FROM tradepi_agent_escalations e
        WHERE n.escalation_id=e.id
          AND e.tenant_id=NEW.tenant_id
          AND e.channel=NEW.channel
          AND e.external_id=NEW.external_id
          AND n.status='pending';
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tradepi_agent_resolve_escalation_assignment_trg ON tradepi_agent_leads;
CREATE TRIGGER tradepi_agent_resolve_escalation_assignment_trg
AFTER UPDATE OF owner_id ON tradepi_agent_leads
FOR EACH ROW EXECUTE FUNCTION tradepi_agent_resolve_escalation_on_assignment();
