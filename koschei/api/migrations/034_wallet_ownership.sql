CREATE TABLE IF NOT EXISTS wallet_signing_challenges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_subject text NOT NULL,
    wallet_address text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    nonce_hash text NOT NULL UNIQUE,
    message text NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS verified_wallet_links (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_subject text NOT NULL,
    wallet_address text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    status text NOT NULL DEFAULT 'active' CHECK (status IN ('active','revoked')),
    verified_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    UNIQUE (network, wallet_address),
    UNIQUE (auth_subject, network)
);

CREATE INDEX IF NOT EXISTS idx_wallet_signing_challenges_subject_expiry
    ON wallet_signing_challenges (auth_subject, expires_at DESC);
CREATE INDEX IF NOT EXISTS idx_verified_wallet_links_subject
    ON verified_wallet_links (auth_subject, network, status);
