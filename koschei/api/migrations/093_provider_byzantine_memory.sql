-- Persistent witness-quality memory for independent Solana RPC providers.
-- This table records only how a provider's canonical witness related to an
-- Evidence Court result. It does not assign a hidden numeric trust score.
CREATE TABLE IF NOT EXISTS public.security_provider_witness_memory (
    network text NOT NULL,
    method text NOT NULL,
    provider text NOT NULL,
    observations bigint NOT NULL DEFAULT 0 CHECK (observations >= 0),
    quorum_agreements bigint NOT NULL DEFAULT 0 CHECK (quorum_agreements >= 0),
    quorum_disagreements bigint NOT NULL DEFAULT 0 CHECK (quorum_disagreements >= 0),
    conflict_observations bigint NOT NULL DEFAULT 0 CHECK (conflict_observations >= 0),
    unavailable_count bigint NOT NULL DEFAULT 0 CHECK (unavailable_count >= 0),
    malformed_count bigint NOT NULL DEFAULT 0 CHECK (malformed_count >= 0),
    rate_limited_count bigint NOT NULL DEFAULT 0 CHECK (rate_limited_count >= 0),
    last_witness_status text NOT NULL DEFAULT '',
    last_error_class text NOT NULL DEFAULT '',
    last_value_hash text NOT NULL DEFAULT '',
    last_context_slot bigint NOT NULL DEFAULT 0 CHECK (last_context_slot >= 0),
    trust_state text NOT NULL DEFAULT 'learning',
    first_observed_at timestamptz NOT NULL DEFAULT now(),
    last_observed_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (network,method,provider),
    CONSTRAINT security_provider_witness_memory_state_check CHECK (
        trust_state IN ('learning','consistent','availability_degraded','divergent','quarantine_candidate')
    )
);

CREATE INDEX IF NOT EXISTS security_provider_witness_memory_state_idx
    ON public.security_provider_witness_memory (network,trust_state,updated_at DESC);

COMMENT ON TABLE public.security_provider_witness_memory IS
    'Historical Evidence Court witness behavior. States are deterministic rule classes, not weighted provider reputation scores.';
