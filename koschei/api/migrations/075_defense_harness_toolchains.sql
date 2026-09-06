CREATE TABLE IF NOT EXISTS defense_harness_plans (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    plan_ref text NOT NULL UNIQUE,
    plan_version text NOT NULL,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    idl_artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    source_artifact_ref text REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    framework text NOT NULL DEFAULT 'anchor',
    framework_version text,
    instruction_count integer NOT NULL,
    account_count integer NOT NULL,
    engine_candidates jsonb NOT NULL DEFAULT '[]'::jsonb,
    plan_json jsonb NOT NULL,
    plan_hash text NOT NULL,
    execution_ready boolean NOT NULL DEFAULT false,
    manual_guidance_required boolean NOT NULL DEFAULT true,
    evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    verdict_authority boolean NOT NULL DEFAULT false,
    created_by text NOT NULL DEFAULT 'owner',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_harness_plans_ref_format CHECK (plan_ref ~ '^KHP1-[0-9a-f]{32}$'),
    CONSTRAINT defense_harness_plans_version_format CHECK (plan_version ~ '^v[0-9]+\.[0-9]+\.[0-9]+$'),
    CONSTRAINT defense_harness_plans_counts_check CHECK (instruction_count > 0 AND account_count >= 0),
    CONSTRAINT defense_harness_plans_engines_array CHECK (jsonb_typeof(engine_candidates) = 'array'),
    CONSTRAINT defense_harness_plans_plan_object CHECK (jsonb_typeof(plan_json) = 'object'),
    CONSTRAINT defense_harness_plans_hash_format CHECK (plan_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_harness_plans_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
    CONSTRAINT defense_harness_plans_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_harness_plans_non_authoritative CHECK (verdict_authority = false)
);

CREATE INDEX IF NOT EXISTS defense_harness_plans_program_idx
    ON defense_harness_plans (program_id, network, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_harness_plans_idl_idx
    ON defense_harness_plans (idl_artifact_ref, created_at DESC);

CREATE TABLE IF NOT EXISTS defense_toolchain_attestations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    attestation_ref text NOT NULL UNIQUE,
    worker_id text NOT NULL,
    tool_name text NOT NULL,
    command text NOT NULL,
    available boolean NOT NULL,
    version_output text NOT NULL DEFAULT '',
    version_hash text NOT NULL,
    evidence_status text NOT NULL,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    attestation_hash text NOT NULL,
    verdict_authority boolean NOT NULL DEFAULT false,
    observed_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_toolchain_attestations_ref_format CHECK (attestation_ref ~ '^KTA1-[0-9a-f]{32}$'),
    CONSTRAINT defense_toolchain_attestations_tool_check CHECK (tool_name IN ('rustc','cargo','solana','anchor','trident')),
    CONSTRAINT defense_toolchain_attestations_evidence_check CHECK (evidence_status IN ('observed','unavailable')),
    CONSTRAINT defense_toolchain_attestations_version_hash_format CHECK (version_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_toolchain_attestations_attestation_hash_format CHECK (attestation_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_toolchain_attestations_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_toolchain_attestations_nonempty CHECK (btrim(worker_id) <> '' AND btrim(command) <> ''),
    CONSTRAINT defense_toolchain_attestations_non_authoritative CHECK (verdict_authority = false)
);

CREATE INDEX IF NOT EXISTS defense_toolchain_attestations_worker_idx
    ON defense_toolchain_attestations (worker_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS defense_toolchain_attestations_tool_idx
    ON defense_toolchain_attestations (tool_name, observed_at DESC);

DROP TRIGGER IF EXISTS defense_harness_plans_immutable ON defense_harness_plans;
CREATE TRIGGER defense_harness_plans_immutable
BEFORE UPDATE OR DELETE ON defense_harness_plans
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();

DROP TRIGGER IF EXISTS defense_toolchain_attestations_immutable ON defense_toolchain_attestations;
CREATE TRIGGER defense_toolchain_attestations_immutable
BEFORE UPDATE OR DELETE ON defense_toolchain_attestations
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
