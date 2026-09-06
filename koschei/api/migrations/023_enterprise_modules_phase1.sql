CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS mev_protection_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    user_wallet text NOT NULL DEFAULT '',
    tx_signature text NOT NULL DEFAULT '',
    estimated_loss_usd numeric(18, 2) NOT NULL DEFAULT 0,
    jito_tip_used boolean NOT NULL DEFAULT false,
    risk_score integer NOT NULL DEFAULT 0,
    risk_level text NOT NULL DEFAULT 'DÜŞÜK',
    route text NOT NULL DEFAULT '',
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_mev_protection_wallet_created ON mev_protection_events (lower(user_wallet), created_at DESC);
CREATE INDEX IF NOT EXISTS idx_mev_protection_signature ON mev_protection_events (tx_signature);

CREATE TABLE IF NOT EXISTS whale_clusters (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    cluster_name text NOT NULL,
    chain text NOT NULL DEFAULT 'solana',
    wallet_count integer NOT NULL DEFAULT 0,
    net_flow_usd numeric(20, 2) NOT NULL DEFAULT 0,
    confidence numeric(5, 4) NOT NULL DEFAULT 0,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_whale_clusters_chain_flow ON whale_clusters (chain, net_flow_usd DESC);

CREATE TABLE IF NOT EXISTS cex_flows (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    exchange text NOT NULL,
    asset_symbol text NOT NULL DEFAULT '',
    direction text NOT NULL CHECK (direction IN ('inflow','outflow','internal','unknown')) DEFAULT 'unknown',
    amount_usd numeric(20, 2) NOT NULL DEFAULT 0,
    tx_signature text NOT NULL DEFAULT '',
    observed_at timestamptz NOT NULL DEFAULT now(),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_cex_flows_exchange_observed ON cex_flows (exchange, observed_at DESC);

CREATE TABLE IF NOT EXISTS liquidity_drain_alerts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    pool_address text NOT NULL DEFAULT '',
    token_mint text NOT NULL DEFAULT '',
    severity text NOT NULL DEFAULT 'DÜŞÜK',
    risk_score integer NOT NULL DEFAULT 0,
    removed_liquidity_usd numeric(20, 2) NOT NULL DEFAULT 0,
    loss_prevented_usd numeric(20, 2) NOT NULL DEFAULT 0,
    telegram_queued boolean NOT NULL DEFAULT false,
    sms_queued boolean NOT NULL DEFAULT false,
    alert_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_liquidity_alerts_pool_created ON liquidity_drain_alerts (pool_address, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_liquidity_alerts_severity ON liquidity_drain_alerts (severity, created_at DESC);

CREATE TABLE IF NOT EXISTS dao_treasuries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    dao_id text NOT NULL,
    treasury_address text NOT NULL,
    chain text NOT NULL DEFAULT 'solana',
    total_value_usd numeric(20, 2) NOT NULL DEFAULT 0,
    signer_count integer NOT NULL DEFAULT 0,
    required_signers integer NOT NULL DEFAULT 0,
    signer_risk_score integer NOT NULL DEFAULT 0,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (dao_id, treasury_address)
);
CREATE INDEX IF NOT EXISTS idx_dao_treasuries_value ON dao_treasuries (total_value_usd DESC);

CREATE TABLE IF NOT EXISTS proposal_risks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    dao_id text NOT NULL DEFAULT '',
    treasury_address text NOT NULL DEFAULT '',
    proposal_id text NOT NULL DEFAULT '',
    risk_score integer NOT NULL DEFAULT 0,
    risk_level text NOT NULL DEFAULT 'DÜŞÜK',
    estimated_outflow_usd numeric(20, 2) NOT NULL DEFAULT 0,
    instruction_count integer NOT NULL DEFAULT 0,
    simulation_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_proposal_risks_dao_created ON proposal_risks (dao_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_proposal_risks_level ON proposal_risks (risk_level, created_at DESC);
