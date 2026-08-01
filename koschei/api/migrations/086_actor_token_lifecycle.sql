-- Evidence-first creator token lifecycle memory.
-- This table stores read-only market observations for creator-linked mints.
-- Current zero liquidity is a fate snapshot; a verified lifetime requires a
-- previously observed positive-liquidity state followed by a later inactive state.
CREATE TABLE IF NOT EXISTS security_actor_token_lifecycle (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network text NOT NULL DEFAULT 'solana-mainnet',
    actor_wallet text NOT NULL,
    mint text NOT NULL,
    creation_signature text NOT NULL DEFAULT '',
    creation_slot bigint,
    created_on_chain_at timestamptz,
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    first_liquid_observed_at timestamptz,
    last_liquid_observed_at timestamptz,
    first_inactive_observed_at timestamptz,
    current_inactive_since timestamptz,
    current_liquidity_usd numeric NOT NULL DEFAULT 0,
    current_price_usd numeric NOT NULL DEFAULT 0,
    fate_status text NOT NULL,
    observation_count bigint NOT NULL DEFAULT 1,
    reactivation_count bigint NOT NULL DEFAULT 0,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT security_actor_token_lifecycle_identity_check CHECK (
        btrim(network) <> '' AND btrim(actor_wallet) <> '' AND btrim(mint) <> ''
    ),
    CONSTRAINT security_actor_token_lifecycle_fate_check CHECK (
        fate_status IN ('active','inactive_or_dead')
    ),
    CONSTRAINT security_actor_token_lifecycle_amount_check CHECK (
        current_liquidity_usd >= 0 AND current_price_usd >= 0 AND
        observation_count >= 1 AND reactivation_count >= 0
    ),
    CONSTRAINT security_actor_token_lifecycle_time_check CHECK (
        first_observed_at <= last_observed_at AND
        (first_liquid_observed_at IS NULL OR first_liquid_observed_at >= first_observed_at) AND
        (last_liquid_observed_at IS NULL OR last_liquid_observed_at >= first_liquid_observed_at) AND
        (first_inactive_observed_at IS NULL OR first_inactive_observed_at >= first_observed_at) AND
        (current_inactive_since IS NULL OR current_inactive_since >= first_observed_at)
    ),
    CONSTRAINT security_actor_token_lifecycle_unique UNIQUE (network,actor_wallet,mint)
);

CREATE INDEX IF NOT EXISTS idx_security_actor_token_lifecycle_actor_fate
    ON security_actor_token_lifecycle (network,actor_wallet,fate_status,last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_actor_token_lifecycle_mint
    ON security_actor_token_lifecycle (network,mint,last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_actor_token_lifecycle_transition
    ON security_actor_token_lifecycle (network,actor_wallet,current_inactive_since)
    WHERE first_liquid_observed_at IS NOT NULL AND current_inactive_since IS NOT NULL;
