CREATE TABLE IF NOT EXISTS tradepi_agent_tenants (
    tenant_id text PRIMARY KEY,
    display_name text NOT NULL,
    vertical text NOT NULL DEFAULT 'general',
    timezone text NOT NULL DEFAULT 'UTC',
    language text NOT NULL DEFAULT 'tr',
    assignment_sla_minutes integer NOT NULL DEFAULT 10 CHECK (assignment_sla_minutes BETWEEN 1 AND 1440),
    followup_delay_minutes integer NOT NULL DEFAULT 120 CHECK (followup_delay_minutes BETWEEN 5 AND 10080),
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

INSERT INTO tradepi_agent_tenants (
    tenant_id, display_name, vertical, timezone, language, assignment_sla_minutes, followup_delay_minutes, status
) VALUES (
    'demo-automotive', 'TradePI Automotive Demo', 'automotive', 'Europe/Istanbul', 'tr', 10, 120, 'active'
)
ON CONFLICT (tenant_id) DO NOTHING;

CREATE OR REPLACE FUNCTION tradepi_agent_enqueue_qualified_followup()
RETURNS trigger AS $$
DECLARE
    delay_minutes integer;
    tenant_status text;
BEGIN
    SELECT followup_delay_minutes, status
    INTO delay_minutes, tenant_status
    FROM tradepi_agent_tenants
    WHERE tenant_id=NEW.tenant_id;

    delay_minutes := COALESCE(delay_minutes, 120);
    tenant_status := COALESCE(tenant_status, 'active');

    IF tenant_status='active' AND NEW.stage='qualified' AND (TG_OP='INSERT' OR OLD.stage IS DISTINCT FROM NEW.stage) THEN
        INSERT INTO tradepi_agent_followups (
            tenant_id, channel, external_id, kind, body, status, due_at, dedupe_key
        ) VALUES (
            NEW.tenant_id,
            NEW.channel,
            NEW.external_id,
            'qualified_lead',
            'İlgilendiğiniz seçeneklerle ilgili yardımcı olmaya devam edebilirim. İsterseniz uygun seçenekleri netleştirelim veya satış temsilcisine aktaralım.',
            'pending',
            now() + make_interval(mins => delay_minutes),
            'qualified:' || NEW.channel || ':' || NEW.external_id
        )
        ON CONFLICT (tenant_id, dedupe_key) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;
