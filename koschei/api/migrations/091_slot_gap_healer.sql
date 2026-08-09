-- Durable replay cursor for the sovereign Solana stream gap healer.
-- The recovery watermark is intentionally separate from the newest live stream
-- row. A reconnecting WSS listener may write newer signatures before the
-- outage window is replayed; using the live head as a cursor would skip that
-- missing interval.
CREATE TABLE IF NOT EXISTS public.security_radar_replay_cursors (
    network text NOT NULL,
    program_id text NOT NULL,
    module_id text NOT NULL,
    event_type text NOT NULL,
    watermark_signature text NOT NULL DEFAULT '',
    watermark_slot bigint NOT NULL DEFAULT 0 CHECK (watermark_slot >= 0),
    scan_head_signature text NOT NULL DEFAULT '',
    scan_head_slot bigint NOT NULL DEFAULT 0 CHECK (scan_head_slot >= 0),
    scan_before_signature text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'bootstrap',
    recovered_event_count bigint NOT NULL DEFAULT 0 CHECK (recovered_event_count >= 0),
    skipped_failed_count bigint NOT NULL DEFAULT 0 CHECK (skipped_failed_count >= 0),
    last_error text NOT NULL DEFAULT '',
    last_scan_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (network, program_id),
    CONSTRAINT security_radar_replay_cursor_status_check CHECK (
        status IN (
            'bootstrap',
            'waiting_for_head',
            'caught_up',
            'backfilling',
            'blocked_history_boundary',
            'rpc_error'
        )
    )
);

CREATE INDEX IF NOT EXISTS security_radar_replay_cursors_status_idx
    ON public.security_radar_replay_cursors (status, updated_at DESC);

CREATE INDEX IF NOT EXISTS security_radar_replay_cursors_watermark_idx
    ON public.security_radar_replay_cursors (network, watermark_slot DESC);

COMMENT ON TABLE public.security_radar_replay_cursors IS
    'Independent recovery watermarks for Solana program-signature replay. Live WSS writes never advance these cursors.';
