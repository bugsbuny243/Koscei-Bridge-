CREATE TABLE IF NOT EXISTS owner_sessions (
    session_hash text PRIMARY KEY,
    wallet_address text,
    user_agent_hash text,
    ip_hash text,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz,
    CONSTRAINT owner_sessions_hash_format CHECK (session_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT owner_sessions_user_agent_hash_format CHECK (user_agent_hash IS NULL OR user_agent_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT owner_sessions_ip_hash_format CHECK (ip_hash IS NULL OR ip_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT owner_sessions_expiry_check CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS owner_sessions_active_expiry_idx
    ON owner_sessions (expires_at)
    WHERE revoked_at IS NULL;

CREATE INDEX IF NOT EXISTS owner_sessions_wallet_idx
    ON owner_sessions (wallet_address, created_at DESC)
    WHERE revoked_at IS NULL;

COMMENT ON TABLE owner_sessions IS 'Server-side owner sessions. Only SHA-256 token hashes are persisted; OWNER_SECRET and plaintext session tokens are never stored.';
