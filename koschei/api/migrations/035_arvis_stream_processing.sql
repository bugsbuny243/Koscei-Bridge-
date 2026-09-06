-- Fresh-schema compatibility: arvis_stream_processing references the raw stream
-- ledger, so the ledger must exist before the foreign key is created. This
-- definition matches the live production schema and remains idempotent on
-- databases where the stream table already exists.
CREATE TABLE IF NOT EXISTS security_radar_stream_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    provider text NOT NULL DEFAULT 'solana_wss',
    stream_mode text NOT NULL DEFAULT 'logs_subscribe',
    network text NOT NULL DEFAULT 'solana-mainnet',
    module_id text NOT NULL DEFAULT 'unknown',
    event_type text NOT NULL DEFAULT 'stream_event',
    target text,
    target_type text NOT NULL DEFAULT 'unknown',
    signature text,
    slot bigint,
    program_id text,
    evidence_quality text NOT NULL DEFAULT 'raw_stream',
    decoded jsonb NOT NULL DEFAULT '{}'::jsonb,
    raw_event jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS security_radar_stream_events_created_idx
    ON security_radar_stream_events (created_at DESC);
CREATE INDEX IF NOT EXISTS security_radar_stream_events_target_idx
    ON security_radar_stream_events (target, created_at DESC)
    WHERE target IS NOT NULL;
CREATE INDEX IF NOT EXISTS security_radar_stream_events_signature_idx
    ON security_radar_stream_events (signature)
    WHERE signature IS NOT NULL;
CREATE INDEX IF NOT EXISTS security_radar_stream_events_slot_idx
    ON security_radar_stream_events (slot DESC)
    WHERE slot IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS security_radar_stream_events_dedupe_idx
    ON security_radar_stream_events (
        COALESCE(signature,''),
        COALESCE(program_id,''),
        module_id,
        event_type,
        COALESCE(target,'')
    )
    WHERE signature IS NOT NULL;

CREATE TABLE IF NOT EXISTS arvis_stream_processing (
    stream_event_id uuid PRIMARY KEY REFERENCES security_radar_stream_events(id) ON DELETE CASCADE,
    target text NOT NULL DEFAULT '',
    signature text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'pending',
    attempts integer NOT NULL DEFAULT 0,
    last_error text NOT NULL DEFAULT '',
    processed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS arvis_stream_processing_status_idx
    ON arvis_stream_processing (status, updated_at DESC);

CREATE INDEX IF NOT EXISTS arvis_stream_processing_target_idx
    ON arvis_stream_processing (target);
