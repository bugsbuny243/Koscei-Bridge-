CREATE TABLE IF NOT EXISTS security_rate_limit_buckets (
    bucket_key_hash text NOT NULL,
    route text NOT NULL,
    window_started_at timestamptz NOT NULL,
    window_seconds integer NOT NULL,
    request_count bigint NOT NULL DEFAULT 0,
    expires_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (bucket_key_hash, route),
    CONSTRAINT security_rate_limit_buckets_hash_format
        CHECK (bucket_key_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT security_rate_limit_buckets_route_nonempty
        CHECK (btrim(route) <> '' AND route LIKE '/api/%'),
    CONSTRAINT security_rate_limit_buckets_window_bounds
        CHECK (window_seconds BETWEEN 1 AND 86400),
    CONSTRAINT security_rate_limit_buckets_count_nonnegative
        CHECK (request_count >= 0),
    CONSTRAINT security_rate_limit_buckets_expiry_order
        CHECK (expires_at > window_started_at)
);

CREATE INDEX IF NOT EXISTS security_rate_limit_buckets_expires_idx
    ON security_rate_limit_buckets (expires_at);

COMMENT ON TABLE security_rate_limit_buckets IS
    'Mutable shared fixed-window counters for security-sensitive HTTP routes. Keys are SHA-256 digests; raw client IPs are not stored here.';
