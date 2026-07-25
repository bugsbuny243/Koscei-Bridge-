ALTER TABLE defense_toolchain_attestations
    DROP CONSTRAINT IF EXISTS defense_toolchain_attestations_tool_check;
ALTER TABLE defense_toolchain_attestations
    ADD CONSTRAINT defense_toolchain_attestations_tool_check
    CHECK (tool_name IN ('rustc','cargo','bwrap','solana','anchor','litesvm','trident'));

ALTER TABLE defense_worker_jobs
    DROP CONSTRAINT IF EXISTS defense_worker_jobs_action_check;
ALTER TABLE defense_worker_jobs
    ADD CONSTRAINT defense_worker_jobs_action_check
    CHECK (action IN ('verify_bundle','run_litesvm_harness'));

CREATE UNIQUE INDEX IF NOT EXISTS defense_worker_jobs_active_litesvm_request_unique
    ON defense_worker_jobs (request_hash)
    WHERE action = 'run_litesvm_harness' AND status IN ('queued','running');

CREATE TABLE IF NOT EXISTS defense_litesvm_execution_attempts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    attempt_ref text NOT NULL UNIQUE,
    attempt_version text NOT NULL,
    job_ref text NOT NULL REFERENCES defense_worker_jobs(job_ref) ON DELETE RESTRICT,
    attempt_number integer NOT NULL,
    profile_ref text NOT NULL REFERENCES defense_harness_execution_profiles(profile_ref) ON DELETE RESTRICT,
    profile_hash text NOT NULL,
    materialization_ref text NOT NULL REFERENCES defense_harness_materializations(materialization_ref) ON DELETE RESTRICT,
    materialization_hash text NOT NULL,
    source_harness_artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    source_harness_artifact_hash text NOT NULL,
    materialized_artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    materialized_artifact_hash text NOT NULL,
    program_id text NOT NULL,
    network text NOT NULL,
    engine text NOT NULL,
    worker_id text NOT NULL,
    worker_image_digest text NOT NULL,
    tool_attestation_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    executable_evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    command_argv jsonb NOT NULL,
    command_hash text NOT NULL,
    sandbox_policy jsonb NOT NULL,
    sandbox_policy_hash text NOT NULL,
    environment_hash text NOT NULL,
    input_hash text NOT NULL,
    cargo_manifest_hash text NOT NULL,
    cargo_lock_hash text NOT NULL,
    max_duration_seconds integer NOT NULL,
    max_output_bytes integer NOT NULL,
    started_at timestamptz NOT NULL,
    completed_at timestamptz NOT NULL,
    duration_ms bigint NOT NULL,
    status text NOT NULL,
    exit_code integer,
    termination_reason text NOT NULL,
    stdout_text text NOT NULL DEFAULT '',
    stderr_text text NOT NULL DEFAULT '',
    stdout_hash text NOT NULL,
    stderr_hash text NOT NULL,
    stdout_truncated boolean NOT NULL DEFAULT false,
    stderr_truncated boolean NOT NULL DEFAULT false,
    evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    network_access boolean NOT NULL DEFAULT false,
    dependency_resolution boolean NOT NULL DEFAULT false,
    wallet_material_accessed boolean NOT NULL DEFAULT false,
    mainnet_rpc_accessed boolean NOT NULL DEFAULT false,
    mainnet_transaction_sent boolean NOT NULL DEFAULT false,
    source_executed boolean NOT NULL DEFAULT false,
    harness_executed boolean NOT NULL DEFAULT false,
    result_hash text NOT NULL,
    verdict_authority boolean NOT NULL DEFAULT false,
    created_by text NOT NULL DEFAULT 'defense-worker',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_litesvm_execution_attempts_ref_format CHECK (attempt_ref ~ '^KLSE1-[0-9a-f]{32}$'),
    CONSTRAINT defense_litesvm_execution_attempts_version_format CHECK (attempt_version ~ '^v[0-9]+\.[0-9]+\.[0-9]+$'),
    CONSTRAINT defense_litesvm_execution_attempts_attempt_positive CHECK (attempt_number > 0),
    CONSTRAINT defense_litesvm_execution_attempts_profile_hash_format CHECK (profile_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_litesvm_execution_attempts_materialization_hash_format CHECK (materialization_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_litesvm_execution_attempts_source_hash_format CHECK (source_harness_artifact_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_litesvm_execution_attempts_artifact_hash_format CHECK (materialized_artifact_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_litesvm_execution_attempts_worker_image_format CHECK (worker_image_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_litesvm_execution_attempts_tool_refs_array CHECK (jsonb_typeof(tool_attestation_refs) = 'array'),
    CONSTRAINT defense_litesvm_execution_attempts_executable_evidence_array CHECK (jsonb_typeof(executable_evidence) = 'array'),
    CONSTRAINT defense_litesvm_execution_attempts_argv_array CHECK (jsonb_typeof(command_argv) = 'array' AND jsonb_array_length(command_argv) = 4),
    CONSTRAINT defense_litesvm_execution_attempts_command_hash_format CHECK (command_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_litesvm_execution_attempts_sandbox_policy_object CHECK (jsonb_typeof(sandbox_policy) = 'object'),
    CONSTRAINT defense_litesvm_execution_attempts_sandbox_policy_hash_format CHECK (sandbox_policy_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_litesvm_execution_attempts_environment_hash_format CHECK (environment_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_litesvm_execution_attempts_input_hash_format CHECK (input_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_litesvm_execution_attempts_cargo_manifest_hash_format CHECK (cargo_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_litesvm_execution_attempts_cargo_lock_hash_format CHECK (cargo_lock_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_litesvm_execution_attempts_budget_bounds CHECK (max_duration_seconds BETWEEN 30 AND 900 AND max_output_bytes BETWEEN 16384 AND 1048576),
    CONSTRAINT defense_litesvm_execution_attempts_time_order CHECK (completed_at >= started_at AND duration_ms >= 0),
    CONSTRAINT defense_litesvm_execution_attempts_status_check CHECK (status IN ('rejected','completed','failed','timed_out','cancelled')),
    CONSTRAINT defense_litesvm_execution_attempts_termination_nonempty CHECK (btrim(termination_reason) <> ''),
    CONSTRAINT defense_litesvm_execution_attempts_stdout_bound CHECK (octet_length(stdout_text) <= 1048576),
    CONSTRAINT defense_litesvm_execution_attempts_stderr_bound CHECK (octet_length(stderr_text) <= 1048576),
    CONSTRAINT defense_litesvm_execution_attempts_stdout_hash_format CHECK (stdout_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_litesvm_execution_attempts_stderr_hash_format CHECK (stderr_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_litesvm_execution_attempts_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
    CONSTRAINT defense_litesvm_execution_attempts_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_litesvm_execution_attempts_result_hash_format CHECK (result_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_litesvm_execution_attempts_no_external_access CHECK (
        network_access = false AND dependency_resolution = false AND wallet_material_accessed = false
        AND mainnet_rpc_accessed = false AND mainnet_transaction_sent = false
    ),
    CONSTRAINT defense_litesvm_execution_attempts_execution_state CHECK (
        (status = 'rejected' AND source_executed = false AND harness_executed = false)
        OR (status IN ('completed','failed','timed_out','cancelled') AND source_executed = true AND harness_executed = true)
    ),
    CONSTRAINT defense_litesvm_execution_attempts_non_authoritative CHECK (verdict_authority = false),
    CONSTRAINT defense_litesvm_execution_attempts_identity_nonempty CHECK (
        btrim(program_id) <> '' AND btrim(network) <> '' AND engine = 'litesvm'
        AND btrim(worker_id) <> ''
    ),
    CONSTRAINT defense_litesvm_execution_attempts_job_attempt_unique UNIQUE (job_ref, attempt_number)
);

CREATE INDEX IF NOT EXISTS defense_litesvm_execution_attempts_profile_idx
    ON defense_litesvm_execution_attempts (profile_ref, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_litesvm_execution_attempts_materialization_idx
    ON defense_litesvm_execution_attempts (materialization_ref, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_litesvm_execution_attempts_job_idx
    ON defense_litesvm_execution_attempts (job_ref, attempt_number DESC);
CREATE INDEX IF NOT EXISTS defense_litesvm_execution_attempts_program_idx
    ON defense_litesvm_execution_attempts (program_id, network, created_at DESC);

DROP TRIGGER IF EXISTS defense_litesvm_execution_attempts_immutable ON defense_litesvm_execution_attempts;
CREATE TRIGGER defense_litesvm_execution_attempts_immutable
BEFORE UPDATE OR DELETE ON defense_litesvm_execution_attempts
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
