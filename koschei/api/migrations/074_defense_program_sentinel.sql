CREATE TABLE IF NOT EXISTS defense_program_monitors (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    monitor_ref text NOT NULL UNIQUE,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    manifest_artifact_ref text REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    active boolean NOT NULL DEFAULT true,
    interval_seconds integer NOT NULL DEFAULT 900,
    next_check_at timestamptz NOT NULL DEFAULT now(),
    lease_owner text,
    lease_expires_at timestamptz,
    last_snapshot_ref text REFERENCES defense_program_deployments(snapshot_ref) ON DELETE RESTRICT,
    last_status text NOT NULL DEFAULT 'pending',
    last_error text,
    last_checked_at timestamptz,
    created_by text NOT NULL DEFAULT 'owner',
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_program_monitors_ref_format CHECK (monitor_ref ~ '^KDM1-[0-9a-f]{32}$'),
    CONSTRAINT defense_program_monitors_interval_check CHECK (interval_seconds BETWEEN 60 AND 86400),
    CONSTRAINT defense_program_monitors_status_check CHECK (last_status IN ('pending','baseline','unchanged','changed','error','disabled')),
    CONSTRAINT defense_program_monitors_identity_unique UNIQUE(program_id, network),
    CONSTRAINT defense_program_monitors_nonempty CHECK (btrim(program_id) <> '' AND btrim(network) <> '')
);

CREATE INDEX IF NOT EXISTS defense_program_monitors_due_idx
    ON defense_program_monitors (active, next_check_at)
    WHERE active = true;

CREATE TABLE IF NOT EXISTS defense_program_change_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_ref text NOT NULL UNIQUE,
    monitor_ref text NOT NULL REFERENCES defense_program_monitors(monitor_ref) ON DELETE RESTRICT,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    previous_snapshot_ref text NOT NULL REFERENCES defense_program_deployments(snapshot_ref) ON DELETE RESTRICT,
    current_snapshot_ref text NOT NULL REFERENCES defense_program_deployments(snapshot_ref) ON DELETE RESTRICT,
    change_types jsonb NOT NULL DEFAULT '[]'::jsonb,
    severity text NOT NULL,
    summary text NOT NULL,
    evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    event_hash text NOT NULL,
    verdict_authority boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_program_change_events_ref_format CHECK (event_ref ~ '^KDCE1-[0-9a-f]{32}$'),
    CONSTRAINT defense_program_change_events_distinct_snapshots CHECK (previous_snapshot_ref <> current_snapshot_ref),
    CONSTRAINT defense_program_change_events_types_array CHECK (jsonb_typeof(change_types) = 'array' AND jsonb_array_length(change_types) > 0),
    CONSTRAINT defense_program_change_events_severity_check CHECK (severity IN ('informational','low','medium','high','critical')),
    CONSTRAINT defense_program_change_events_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
    CONSTRAINT defense_program_change_events_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_program_change_events_hash_format CHECK (event_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_program_change_events_non_authoritative CHECK (verdict_authority = false)
);

CREATE INDEX IF NOT EXISTS defense_program_change_events_program_idx
    ON defense_program_change_events (program_id, network, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_program_change_events_monitor_idx
    ON defense_program_change_events (monitor_ref, created_at DESC);

DROP TRIGGER IF EXISTS defense_program_change_events_immutable ON defense_program_change_events;
CREATE TRIGGER defense_program_change_events_immutable
BEFORE UPDATE OR DELETE ON defense_program_change_events
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
