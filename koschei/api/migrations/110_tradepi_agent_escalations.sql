CREATE TABLE IF NOT EXISTS tradepi_agent_escalations (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL,
    channel text NOT NULL,
    external_id text NOT NULL,
    kind text NOT NULL,
    reason text NOT NULL,
    status text NOT NULL DEFAULT 'open' CHECK (status IN ('open','acknowledged','resolved')),
    dedupe_key text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    acknowledged_at timestamptz,
    resolved_at timestamptz,
    UNIQUE (tenant_id, dedupe_key)
);

CREATE INDEX IF NOT EXISTS tradepi_agent_escalations_open_idx
    ON tradepi_agent_escalations (tenant_id, status, created_at ASC);
