ALTER TABLE tradepi_agent_leads
    ADD COLUMN IF NOT EXISTS owner_id text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS crm_status text NOT NULL DEFAULT 'unassigned',
    ADD COLUMN IF NOT EXISTS crm_external_id text NOT NULL DEFAULT '';

CREATE INDEX IF NOT EXISTS tradepi_agent_leads_owner_idx
    ON tradepi_agent_leads (tenant_id, owner_id, score DESC, updated_at DESC);

ALTER TABLE tradepi_agent_appointment_requests
    ADD COLUMN IF NOT EXISTS calendar_provider text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS calendar_event_id text NOT NULL DEFAULT '';

CREATE TABLE IF NOT EXISTS tradepi_agent_revenue_events (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    channel text NOT NULL,
    external_id text NOT NULL,
    amount_minor bigint NOT NULL CHECK (amount_minor > 0),
    currency text NOT NULL CHECK (char_length(currency) BETWEEN 3 AND 8),
    source text NOT NULL CHECK (char_length(trim(source)) > 0),
    evidence_ref text NOT NULL CHECK (char_length(trim(evidence_ref)) > 0),
    status text NOT NULL DEFAULT 'verified' CHECK (status IN ('verified','reversed')),
    occurred_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (tenant_id, source, evidence_ref)
);

CREATE INDEX IF NOT EXISTS tradepi_agent_revenue_events_lookup_idx
    ON tradepi_agent_revenue_events (tenant_id, occurred_at DESC);

CREATE INDEX IF NOT EXISTS tradepi_agent_revenue_events_lead_idx
    ON tradepi_agent_revenue_events (tenant_id, channel, external_id, occurred_at DESC);
