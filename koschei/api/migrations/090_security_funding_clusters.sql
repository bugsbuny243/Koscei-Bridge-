-- Persistent cross-token funding-cluster memory.
-- Rows are written only from observed holder-cluster groups; no placeholder
-- wallets, signatures, slots or amounts are synthesized to complete a row.
CREATE TABLE IF NOT EXISTS public.security_funding_clusters (
    funding_source text NOT NULL,
    cluster_kind text NOT NULL,
    target text NOT NULL,
    network text NOT NULL,
    member_count integer NOT NULL CHECK (member_count >= 2),
    member_wallets jsonb NOT NULL CHECK (jsonb_typeof(member_wallets) = 'array'),
    holder_percentage double precision,
    synchronization_slot_spread bigint,
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    observation_count integer NOT NULL DEFAULT 1 CHECK (observation_count >= 1),
    PRIMARY KEY (funding_source, cluster_kind, target, network),
    CONSTRAINT security_funding_clusters_kind_check
        CHECK (cluster_kind IN ('shared_funder','same_amount')),
    CONSTRAINT security_funding_clusters_time_check
        CHECK (first_observed_at <= last_observed_at),
    CONSTRAINT security_funding_clusters_holder_percentage_check
        CHECK (holder_percentage IS NULL OR (holder_percentage >= 0 AND holder_percentage <= 100)),
    CONSTRAINT security_funding_clusters_slot_spread_check
        CHECK (synchronization_slot_spread IS NULL OR synchronization_slot_spread >= 0)
);

CREATE TABLE IF NOT EXISTS public.security_funding_cluster_actors (
    funding_source text NOT NULL,
    network text NOT NULL,
    distinct_targets integer NOT NULL DEFAULT 0 CHECK (distinct_targets >= 0),
    total_member_wallets integer NOT NULL DEFAULT 0 CHECK (total_member_wallets >= 0),
    max_member_count integer NOT NULL DEFAULT 0 CHECK (max_member_count >= 0),
    first_observed_at timestamptz NOT NULL,
    last_observed_at timestamptz NOT NULL,
    PRIMARY KEY (funding_source, network),
    CONSTRAINT security_funding_cluster_actors_time_check
        CHECK (first_observed_at <= last_observed_at)
);

CREATE INDEX IF NOT EXISTS idx_security_funding_clusters_source_network
    ON public.security_funding_clusters (funding_source, network);

CREATE INDEX IF NOT EXISTS idx_security_funding_cluster_actors_targets
    ON public.security_funding_cluster_actors (distinct_targets DESC);
