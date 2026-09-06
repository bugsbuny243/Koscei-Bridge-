ALTER TABLE defense_toolchain_attestations
    ADD COLUMN IF NOT EXISTS worker_image_digest text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS binary_path text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS binary_hash text NOT NULL DEFAULT '';

ALTER TABLE defense_toolchain_attestations
    ADD CONSTRAINT defense_toolchain_attestations_image_digest_format
        CHECK (worker_image_digest = '' OR worker_image_digest ~ '^sha256:[0-9a-f]{64}$'),
    ADD CONSTRAINT defense_toolchain_attestations_binary_hash_format
        CHECK (binary_hash = '' OR binary_hash ~ '^sha256:[0-9a-f]{64}$'),
    ADD CONSTRAINT defense_toolchain_attestations_binary_pin_consistency
        CHECK ((binary_path = '' AND binary_hash = '') OR (btrim(binary_path) <> '' AND binary_hash ~ '^sha256:[0-9a-f]{64}$'));

CREATE TABLE IF NOT EXISTS defense_harness_execution_profiles (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    profile_ref text NOT NULL UNIQUE,
    profile_version text NOT NULL,
    plan_ref text NOT NULL REFERENCES defense_harness_plans(plan_ref) ON DELETE RESTRICT,
    harness_artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    engine text NOT NULL,
    worker_id text NOT NULL,
    worker_image_digest text NOT NULL,
    required_tools jsonb NOT NULL DEFAULT '[]'::jsonb,
    tool_pins jsonb NOT NULL DEFAULT '[]'::jsonb,
    confirmed_invariants jsonb NOT NULL DEFAULT '[]'::jsonb,
    command_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
    max_duration_seconds integer NOT NULL,
    max_output_bytes integer NOT NULL,
    readiness_status text NOT NULL,
    execution_allowed boolean NOT NULL DEFAULT false,
    evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    profile_hash text NOT NULL,
    verdict_authority boolean NOT NULL DEFAULT false,
    created_by text NOT NULL DEFAULT 'owner',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_harness_execution_profiles_ref_format CHECK (profile_ref ~ '^KHEP1-[0-9a-f]{32}$'),
    CONSTRAINT defense_harness_execution_profiles_version_format CHECK (profile_version ~ '^v[0-9]+\.[0-9]+\.[0-9]+$'),
    CONSTRAINT defense_harness_execution_profiles_engine_check CHECK (engine IN ('litesvm','trident')),
    CONSTRAINT defense_harness_execution_profiles_worker_nonempty CHECK (btrim(worker_id) <> ''),
    CONSTRAINT defense_harness_execution_profiles_image_digest_format CHECK (worker_image_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_harness_execution_profiles_required_tools_array CHECK (jsonb_typeof(required_tools) = 'array'),
    CONSTRAINT defense_harness_execution_profiles_tool_pins_array CHECK (jsonb_typeof(tool_pins) = 'array'),
    CONSTRAINT defense_harness_execution_profiles_invariants_array CHECK (jsonb_typeof(confirmed_invariants) = 'array'),
    CONSTRAINT defense_harness_execution_profiles_command_policy_object CHECK (jsonb_typeof(command_policy) = 'object'),
    CONSTRAINT defense_harness_execution_profiles_duration_check CHECK (max_duration_seconds BETWEEN 30 AND 900),
    CONSTRAINT defense_harness_execution_profiles_output_check CHECK (max_output_bytes BETWEEN 16384 AND 1048576),
    CONSTRAINT defense_harness_execution_profiles_status_check CHECK (readiness_status IN ('ready','blocked')),
    CONSTRAINT defense_harness_execution_profiles_status_consistency CHECK (
        (readiness_status = 'ready' AND execution_allowed = true)
        OR (readiness_status = 'blocked' AND execution_allowed = false)
    ),
    CONSTRAINT defense_harness_execution_profiles_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
    CONSTRAINT defense_harness_execution_profiles_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_harness_execution_profiles_hash_format CHECK (profile_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_harness_execution_profiles_non_authoritative CHECK (verdict_authority = false)
);

CREATE INDEX IF NOT EXISTS defense_harness_execution_profiles_plan_idx
    ON defense_harness_execution_profiles (plan_ref, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_harness_execution_profiles_worker_idx
    ON defense_harness_execution_profiles (worker_id, created_at DESC);

DROP TRIGGER IF EXISTS defense_harness_execution_profiles_immutable ON defense_harness_execution_profiles;
CREATE TRIGGER defense_harness_execution_profiles_immutable
BEFORE UPDATE OR DELETE ON defense_harness_execution_profiles
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
