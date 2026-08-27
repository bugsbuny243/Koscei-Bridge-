CREATE OR REPLACE FUNCTION tradepi_agent_enqueue_calendar_confirmation()
RETURNS trigger AS $$
BEGIN
    IF NEW.status = 'confirmed' AND OLD.status IS DISTINCT FROM 'confirmed' THEN
        INSERT INTO tradepi_agent_integration_outbox (
            tenant_id, event_type, aggregate_id, payload, status, next_attempt_at
        ) VALUES (
            NEW.tenant_id,
            'calendar.appointment.confirmed',
            NEW.id::text,
            jsonb_build_object(
                'appointment_id', NEW.id,
                'tenant_id', NEW.tenant_id,
                'channel', NEW.channel,
                'external_id', NEW.external_id,
                'request_text', NEW.request_text,
                'scheduled_for', NEW.scheduled_for,
                'calendar_provider', NEW.calendar_provider,
                'calendar_event_id', NEW.calendar_event_id
            ),
            'pending',
            now()
        )
        ON CONFLICT (tenant_id, event_type, aggregate_id) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tradepi_agent_calendar_confirmation_outbox_trg
    ON tradepi_agent_appointment_requests;

CREATE TRIGGER tradepi_agent_calendar_confirmation_outbox_trg
AFTER UPDATE OF status ON tradepi_agent_appointment_requests
FOR EACH ROW
EXECUTE FUNCTION tradepi_agent_enqueue_calendar_confirmation();
