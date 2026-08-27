CREATE TABLE IF NOT EXISTS tradepi_agent_integration_outbox (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    event_type text NOT NULL,
    aggregate_id text NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending' CHECK (status IN ('pending','processing','delivered')),
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    last_error text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now(),
    delivered_at timestamptz,
    UNIQUE (tenant_id, event_type, aggregate_id)
);

CREATE INDEX IF NOT EXISTS tradepi_agent_integration_outbox_pending_idx
    ON tradepi_agent_integration_outbox (status, next_attempt_at, id);
