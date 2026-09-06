-- Persistent, transaction-referenced on-chain event memory.
-- An event is stored only when it carries a real transaction signature and slot.
CREATE TABLE IF NOT EXISTS public.security_actor_exit_events (
    actor_wallet text NOT NULL,
    network text NOT NULL,
    target text NOT NULL,
    event_kind text NOT NULL,
    evidence_state text NOT NULL,
    signature text NOT NULL CHECK (btrim(signature) <> ''),
    slot bigint NOT NULL CHECK (slot > 0),
    observed_at timestamptz NOT NULL,
    source_rule_id text NOT NULL,
    detail jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(detail) = 'object'),
    PRIMARY KEY (actor_wallet, network, target, event_kind, signature),
    CONSTRAINT security_actor_exit_events_kind_check CHECK (
        event_kind IN (
            'liquidity_removal',
            'dominant_holder_exit',
            'authority_change_post_launch',
            'supply_growth_post_launch',
            'creator_sell'
        )
    ),
    CONSTRAINT security_actor_exit_events_state_check
        CHECK (evidence_state IN ('verified','observed'))
);

CREATE TABLE IF NOT EXISTS public.security_actor_exit_profiles (
    actor_wallet text NOT NULL,
    network text NOT NULL,
    distinct_targets_with_events integer NOT NULL DEFAULT 0 CHECK (distinct_targets_with_events >= 0),
    event_kind_counts jsonb NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(event_kind_counts) = 'object'),
    verified_event_count integer NOT NULL DEFAULT 0 CHECK (verified_event_count >= 0),
    observed_event_count integer NOT NULL DEFAULT 0 CHECK (observed_event_count >= 0),
    first_event_at timestamptz,
    last_event_at timestamptz,
    PRIMARY KEY (actor_wallet, network),
    CONSTRAINT security_actor_exit_profiles_time_check
        CHECK (first_event_at IS NULL OR last_event_at IS NULL OR first_event_at <= last_event_at)
);

CREATE INDEX IF NOT EXISTS idx_security_actor_exit_events_actor_network
    ON public.security_actor_exit_events (actor_wallet, network);

CREATE INDEX IF NOT EXISTS idx_security_actor_exit_profiles_targets
    ON public.security_actor_exit_profiles (distinct_targets_with_events DESC);
