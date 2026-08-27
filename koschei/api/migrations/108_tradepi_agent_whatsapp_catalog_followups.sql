CREATE TABLE IF NOT EXISTS tradepi_agent_provider_events (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    channel text NOT NULL,
    provider_message_id text NOT NULL,
    received_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, channel, provider_message_id)
);

CREATE TABLE IF NOT EXISTS tradepi_agent_catalog_items (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    sku text NOT NULL,
    kind text NOT NULL DEFAULT 'product',
    name text NOT NULL,
    description text NOT NULL DEFAULT '',
    price_minor bigint CHECK (price_minor IS NULL OR price_minor >= 0),
    currency text NOT NULL DEFAULT 'TRY',
    availability text NOT NULL DEFAULT 'unknown' CHECK (availability IN ('unknown','available','unavailable')),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, sku)
);

CREATE INDEX IF NOT EXISTS tradepi_agent_catalog_lookup_idx
    ON tradepi_agent_catalog_items (tenant_id, availability, updated_at DESC);

CREATE TABLE IF NOT EXISTS tradepi_agent_knowledge_entries (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    key text NOT NULL,
    title text NOT NULL,
    body text NOT NULL,
    source_url text NOT NULL DEFAULT '',
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, key)
);

CREATE TABLE IF NOT EXISTS tradepi_agent_followups (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    channel text NOT NULL,
    external_id text NOT NULL,
    kind text NOT NULL,
    body text NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','sent','cancelled','failed')),
    due_at timestamptz NOT NULL,
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error text NOT NULL DEFAULT '',
    dedupe_key text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    sent_at timestamptz,
    UNIQUE (tenant_id, dedupe_key)
);

CREATE INDEX IF NOT EXISTS tradepi_agent_followups_pending_idx
    ON tradepi_agent_followups (due_at, id)
    WHERE status='pending';

CREATE OR REPLACE FUNCTION tradepi_agent_enqueue_qualified_followup()
RETURNS trigger AS $$
BEGIN
    IF NEW.stage='qualified' AND (TG_OP='INSERT' OR OLD.stage IS DISTINCT FROM NEW.stage) THEN
        INSERT INTO tradepi_agent_followups (
            tenant_id, channel, external_id, kind, body, status, due_at, dedupe_key
        ) VALUES (
            NEW.tenant_id,
            NEW.channel,
            NEW.external_id,
            'qualified_lead',
            'İlgilendiğiniz seçeneklerle ilgili yardımcı olmaya devam edebilirim. İsterseniz uygun seçenekleri netleştirelim veya satış temsilcisine aktaralım.',
            'pending',
            now() + interval '2 hours',
            'qualified:' || NEW.channel || ':' || NEW.external_id
        )
        ON CONFLICT (tenant_id, dedupe_key) DO NOTHING;
    END IF;
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS tradepi_agent_qualified_followup_trg ON tradepi_agent_leads;
CREATE TRIGGER tradepi_agent_qualified_followup_trg
AFTER INSERT OR UPDATE OF stage ON tradepi_agent_leads
FOR EACH ROW EXECUTE FUNCTION tradepi_agent_enqueue_qualified_followup();
