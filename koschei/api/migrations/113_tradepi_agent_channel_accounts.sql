CREATE TABLE IF NOT EXISTS tradepi_agent_channel_accounts (
    id bigserial PRIMARY KEY,
    tenant_id text NOT NULL REFERENCES tradepi_agent_tenants(tenant_id) ON DELETE CASCADE,
    channel text NOT NULL CHECK (channel IN ('web','telegram','whatsapp')),
    account_key text NOT NULL,
    provider_account_id text NOT NULL DEFAULT '',
    allowed_origin text NOT NULL DEFAULT '',
    label text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','disabled')),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (account_key),
    UNIQUE (channel, provider_account_id)
);

CREATE INDEX IF NOT EXISTS tradepi_agent_channel_accounts_tenant_idx
    ON tradepi_agent_channel_accounts (tenant_id, channel, status, updated_at DESC);

INSERT INTO tradepi_agent_channel_accounts (
    tenant_id, channel, account_key, provider_account_id, allowed_origin, label, status
) VALUES (
    'demo-automotive', 'web', 'demo-web-v1', 'tradepi-demo-web', 'https://tradepigloball.co', 'TradePI demo web widget', 'active'
)
ON CONFLICT (account_key) DO NOTHING;
