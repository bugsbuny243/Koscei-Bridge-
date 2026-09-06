CREATE TABLE IF NOT EXISTS api_organizations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    slug text NOT NULL UNIQUE,
    name text NOT NULL,
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','review','suspended','closed')),
    contract_tier text NOT NULL DEFAULT 'standard',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS api_key_organizations (
    api_key_id uuid PRIMARY KEY REFERENCES api_keys(id) ON DELETE CASCADE,
    organization_id uuid NOT NULL REFERENCES api_organizations(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS entity_wallet_labels (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network text NOT NULL DEFAULT 'solana-mainnet',
    wallet_address text NOT NULL,
    entity_type text NOT NULL DEFAULT 'unknown',
    entity_name text NOT NULL DEFAULT '',
    confidence numeric(5,4) NOT NULL DEFAULT 0 CHECK (confidence >= 0 AND confidence <= 1),
    evidence_source text NOT NULL DEFAULT '',
    evidence_url text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'observed' CHECK (status IN ('observed','verified','disputed','expired')),
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    verified_at timestamptz,
    expires_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (network, wallet_address, entity_name)
);

CREATE TABLE IF NOT EXISTS api_access_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    organization_id uuid REFERENCES api_organizations(id) ON DELETE CASCADE,
    api_key_id uuid REFERENCES api_keys(id) ON DELETE CASCADE,
    auth_subject text,
    decision text NOT NULL DEFAULT 'allow' CHECK (decision IN ('allow','throttle','enterprise_review','temporary_hold','deny')),
    reason_code text NOT NULL DEFAULT 'manual_policy',
    reason_detail text NOT NULL DEFAULT '',
    rate_limit_multiplier numeric(6,4) NOT NULL DEFAULT 1 CHECK (rate_limit_multiplier > 0 AND rate_limit_multiplier <= 1),
    evidence_confidence numeric(5,4) NOT NULL DEFAULT 1 CHECK (evidence_confidence >= 0 AND evidence_confidence <= 1),
    active boolean NOT NULL DEFAULT true,
    starts_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz,
    created_by text NOT NULL DEFAULT 'owner',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CHECK (organization_id IS NOT NULL OR api_key_id IS NOT NULL OR NULLIF(auth_subject,'') IS NOT NULL),
    CHECK (decision NOT IN ('temporary_hold','deny') OR evidence_confidence >= 0.90)
);

CREATE TABLE IF NOT EXISTS api_access_decisions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    api_key_id uuid REFERENCES api_keys(id) ON DELETE SET NULL,
    organization_id uuid REFERENCES api_organizations(id) ON DELETE SET NULL,
    auth_subject text NOT NULL DEFAULT '',
    endpoint text NOT NULL DEFAULT '',
    decision text NOT NULL,
    reason_code text NOT NULL DEFAULT '',
    policy_id uuid REFERENCES api_access_policies(id) ON DELETE SET NULL,
    request_ip text NOT NULL DEFAULT '',
    user_agent text NOT NULL DEFAULT '',
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_entity_wallet_labels_address
    ON entity_wallet_labels (network, wallet_address, status, confidence DESC);
CREATE INDEX IF NOT EXISTS idx_api_access_policies_api_key
    ON api_access_policies (api_key_id, active, expires_at);
CREATE INDEX IF NOT EXISTS idx_api_access_policies_subject
    ON api_access_policies (auth_subject, active, expires_at);
CREATE INDEX IF NOT EXISTS idx_api_access_policies_org
    ON api_access_policies (organization_id, active, expires_at);
CREATE INDEX IF NOT EXISTS idx_api_access_decisions_key_created
    ON api_access_decisions (api_key_id, created_at DESC);
