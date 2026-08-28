CREATE TABLE IF NOT EXISTS tradepi_agent_pilot_leads (
    id BIGSERIAL PRIMARY KEY,
    business_name TEXT NOT NULL,
    contact_name TEXT NOT NULL,
    email TEXT NOT NULL,
    phone TEXT NOT NULL DEFAULT '',
    website TEXT NOT NULL,
    vertical TEXT NOT NULL DEFAULT 'general',
    monthly_lead_band TEXT NOT NULL DEFAULT 'unknown',
    message TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'new',
    source TEXT NOT NULL DEFAULT 'agents-page',
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT tradepi_agent_pilot_status_check CHECK (status IN ('new','contacted','qualified','won','lost'))
);

CREATE INDEX IF NOT EXISTS tradepi_agent_pilot_leads_status_created_idx
    ON tradepi_agent_pilot_leads (status, created_at DESC);

CREATE INDEX IF NOT EXISTS tradepi_agent_pilot_leads_email_idx
    ON tradepi_agent_pilot_leads (LOWER(email));
