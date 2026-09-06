ALTER TABLE tradepi_agent_leads
    ADD COLUMN IF NOT EXISTS channel_account_id bigint REFERENCES tradepi_agent_channel_accounts(id) ON DELETE SET NULL;

ALTER TABLE tradepi_agent_messages
    ADD COLUMN IF NOT EXISTS channel_account_id bigint REFERENCES tradepi_agent_channel_accounts(id) ON DELETE SET NULL;

ALTER TABLE tradepi_agent_followups
    ADD COLUMN IF NOT EXISTS channel_account_id bigint REFERENCES tradepi_agent_channel_accounts(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS tradepi_agent_leads_channel_account_idx
    ON tradepi_agent_leads (tenant_id, channel_account_id, updated_at DESC);

UPDATE tradepi_agent_leads l
SET channel_account_id=a.id
FROM tradepi_agent_channel_accounts a
WHERE l.channel_account_id IS NULL
  AND l.tenant_id=a.tenant_id
  AND l.channel=a.channel
  AND a.status='active'
  AND a.tenant_id='demo-automotive'
  AND a.channel='web';

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
            tenant_id, channel, external_id, channel_account_id, kind, body, status, due_at, dedupe_key
        ) VALUES (
            NEW.tenant_id,
            NEW.channel,
            NEW.external_id,
            NEW.channel_account_id,
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
