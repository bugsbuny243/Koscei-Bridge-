CREATE TABLE IF NOT EXISTS transaction_firewall_reports (
    request_id text PRIMARY KEY,
    api_key_id uuid,
    actor_subject text NOT NULL DEFAULT '',
    actor_email text NOT NULL DEFAULT '',
    transaction_fingerprint text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    encoding text NOT NULL DEFAULT 'base64',
    action text NOT NULL,
    risk_level text NOT NULL,
    risk_index integer NOT NULL DEFAULT 0 CHECK (risk_index >= 0 AND risk_index <= 100),
    simulation_ok boolean NOT NULL DEFAULT false,
    simulation_error jsonb NOT NULL DEFAULT '{}'::jsonb,
    units_consumed bigint NOT NULL DEFAULT 0,
    program_ids jsonb NOT NULL DEFAULT '[]'::jsonb,
    findings jsonb NOT NULL DEFAULT '[]'::jsonb,
    logs jsonb NOT NULL DEFAULT '[]'::jsonb,
    shadow_mode boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_transaction_firewall_reports_api_key_created
    ON transaction_firewall_reports (api_key_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_transaction_firewall_reports_fingerprint_created
    ON transaction_firewall_reports (transaction_fingerprint, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_transaction_firewall_reports_action_created
    ON transaction_firewall_reports (action, created_at DESC);
