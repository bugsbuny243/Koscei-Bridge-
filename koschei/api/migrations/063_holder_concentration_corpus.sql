CREATE TABLE IF NOT EXISTS holder_concentration_observations (
    network text NOT NULL DEFAULT 'solana-mainnet',
    mint text NOT NULL,
    owner_wallet text NOT NULL,
    top_owner_share_pct numeric(9,4) NOT NULL,
    first_observed_at timestamptz NOT NULL DEFAULT now(),
    last_observed_at timestamptz NOT NULL DEFAULT now(),
    scan_count bigint NOT NULL DEFAULT 1,
    PRIMARY KEY (network,mint),
    CONSTRAINT holder_concentration_share_range CHECK (top_owner_share_pct >= 0 AND top_owner_share_pct <= 100),
    CONSTRAINT holder_concentration_observation_nonempty CHECK (btrim(network) <> '' AND btrim(mint) <> '' AND btrim(owner_wallet) <> '')
);

CREATE INDEX IF NOT EXISTS idx_holder_concentration_observations_share
    ON holder_concentration_observations (top_owner_share_pct DESC);

CREATE TABLE IF NOT EXISTS holder_concentration_corpus_stats (
    stats_key text PRIMARY KEY,
    sample_count bigint NOT NULL DEFAULT 0 CHECK (sample_count >= 0),
    bucket_width numeric(8,4) NOT NULL DEFAULT 1 CHECK (bucket_width > 0),
    bucket_counts jsonb NOT NULL DEFAULT '[]'::jsonb,
    calculated_at timestamptz NOT NULL DEFAULT now(),
    source_window_start timestamptz,
    source_window_end timestamptz,
    CONSTRAINT holder_corpus_bucket_array CHECK (jsonb_typeof(bucket_counts) = 'array')
);

INSERT INTO holder_concentration_corpus_stats
(stats_key,sample_count,bucket_width,bucket_counts,calculated_at)
VALUES ('owner_resolved_top_share_v1',0,1,'[]'::jsonb,now())
ON CONFLICT (stats_key) DO NOTHING;
