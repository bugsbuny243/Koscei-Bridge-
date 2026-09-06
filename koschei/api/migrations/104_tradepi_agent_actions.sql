CREATE TABLE IF NOT EXISTS tradepi_agent_handoffs (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    channel text NOT NULL,
    external_id text NOT NULL,
    reason text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'requested',
    requested_at timestamptz NOT NULL DEFAULT now(),
    resolved_at timestamptz
);

CREATE INDEX IF NOT EXISTS tradepi_agent_handoffs_lookup_idx
    ON tradepi_agent_handoffs (tenant_id, channel, external_id, requested_at DESC);

CREATE TABLE IF NOT EXISTS tradepi_agent_appointment_requests (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    channel text NOT NULL,
    external_id text NOT NULL,
    request_text text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'requested',
    scheduled_for timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS tradepi_agent_appointment_requests_lookup_idx
    ON tradepi_agent_appointment_requests (tenant_id, channel, external_id, created_at DESC);
