CREATE TABLE IF NOT EXISTS defense_worker_jobs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    job_ref text NOT NULL UNIQUE,
    action text NOT NULL,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    source_artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    finding_ref text,
    patch_ref text,
    request_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    request_hash text NOT NULL,
    status text NOT NULL DEFAULT 'queued',
    progress integer NOT NULL DEFAULT 0,
    attempts integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 2,
    worker_id text,
    lease_expires_at timestamptz,
    result_payload jsonb,
    result_hash text,
    error_code text,
    error_message text,
    queued_at timestamptz NOT NULL DEFAULT now(),
    started_at timestamptz,
    completed_at timestamptz,
    failed_at timestamptz,
    updated_at timestamptz NOT NULL DEFAULT now(),
    created_by text NOT NULL DEFAULT 'owner',
    CONSTRAINT defense_worker_jobs_ref_format CHECK (job_ref ~ '^KDW1-[0-9a-f]{32}$'),
    CONSTRAINT defense_worker_jobs_action_check CHECK (action IN ('verify_bundle')),
    CONSTRAINT defense_worker_jobs_request_object CHECK (jsonb_typeof(request_payload) = 'object'),
    CONSTRAINT defense_worker_jobs_request_hash_format CHECK (request_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_worker_jobs_result_hash_format CHECK (result_hash IS NULL OR result_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_worker_jobs_status_check CHECK (status IN ('queued','running','completed','failed','cancelled')),
    CONSTRAINT defense_worker_jobs_progress_check CHECK (progress BETWEEN 0 AND 100),
    CONSTRAINT defense_worker_jobs_attempts_check CHECK (attempts >= 0 AND max_attempts BETWEEN 1 AND 5),
    CONSTRAINT defense_worker_jobs_nonempty CHECK (btrim(program_id) <> '' AND btrim(network) <> '')
);

CREATE INDEX IF NOT EXISTS defense_worker_jobs_claim_idx
    ON defense_worker_jobs (status, queued_at)
    WHERE status IN ('queued','running');
CREATE INDEX IF NOT EXISTS defense_worker_jobs_program_idx
    ON defense_worker_jobs (program_id, network, queued_at DESC);
CREATE INDEX IF NOT EXISTS defense_worker_jobs_artifact_idx
    ON defense_worker_jobs (source_artifact_ref, queued_at DESC);

CREATE TABLE IF NOT EXISTS defense_worker_job_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_ref text NOT NULL UNIQUE,
    job_ref text NOT NULL REFERENCES defense_worker_jobs(job_ref) ON DELETE RESTRICT,
    event_type text NOT NULL,
    worker_id text,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    event_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_worker_job_events_ref_format CHECK (event_ref ~ '^KDWE1-[0-9a-f]{32}$'),
    CONSTRAINT defense_worker_job_events_type_check CHECK (event_type IN ('queued','claimed','completed','failed','lease_recovered','cancelled')),
    CONSTRAINT defense_worker_job_events_payload_object CHECK (jsonb_typeof(payload) = 'object'),
    CONSTRAINT defense_worker_job_events_hash_format CHECK (event_hash ~ '^sha256:[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS defense_worker_job_events_job_idx
    ON defense_worker_job_events (job_ref, created_at ASC);

DROP TRIGGER IF EXISTS defense_worker_job_events_immutable ON defense_worker_job_events;
CREATE TRIGGER defense_worker_job_events_immutable
BEFORE UPDATE OR DELETE ON defense_worker_job_events
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
