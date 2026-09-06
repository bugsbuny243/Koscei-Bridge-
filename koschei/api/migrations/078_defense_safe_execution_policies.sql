CREATE TABLE IF NOT EXISTS defense_toolchain_policies (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    policy_ref text NOT NULL UNIQUE,
    policy_version text NOT NULL,
    worker_image_digest text NOT NULL,
    required_tools jsonb NOT NULL,
    policy_hash text NOT NULL,
    verdict_authority boolean NOT NULL DEFAULT false,
    created_by text NOT NULL DEFAULT 'owner',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_toolchain_policies_ref_format CHECK (policy_ref ~ '^KTP1-[0-9a-f]{32}$'),
    CONSTRAINT defense_toolchain_policies_version_format CHECK (policy_version ~ '^v[0-9]+\.[0-9]+\.[0-9]+$'),
    CONSTRAINT defense_toolchain_policies_image_digest_format CHECK (worker_image_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_toolchain_policies_required_tools_object CHECK (jsonb_typeof(required_tools) = 'object'),
    CONSTRAINT defense_toolchain_policies_policy_hash_format CHECK (policy_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_toolchain_policies_non_authoritative CHECK (verdict_authority = false)
);

CREATE INDEX IF NOT EXISTS defense_toolchain_policies_created_idx
    ON defense_toolchain_policies (created_at DESC);

CREATE TABLE IF NOT EXISTS defense_safe_execution_manifests (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    manifest_ref text NOT NULL UNIQUE,
    manifest_version text NOT NULL,
    plan_ref text NOT NULL REFERENCES defense_harness_plans(plan_ref) ON DELETE RESTRICT,
    policy_ref text NOT NULL REFERENCES defense_toolchain_policies(policy_ref) ON DELETE RESTRICT,
    engine text NOT NULL,
    fixture_hashes jsonb NOT NULL DEFAULT '{}'::jsonb,
    argument_hashes jsonb NOT NULL DEFAULT '{}'::jsonb,
    invariant_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    deterministic_seed bigint NOT NULL,
    execution_budgets jsonb NOT NULL,
    owner_approved boolean NOT NULL DEFAULT false,
    execution_ready boolean NOT NULL DEFAULT false,
    manifest_hash text NOT NULL,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    verdict_authority boolean NOT NULL DEFAULT false,
    created_by text NOT NULL DEFAULT 'owner',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_safe_execution_manifests_ref_format CHECK (manifest_ref ~ '^KEM1-[0-9a-f]{32}$'),
    CONSTRAINT defense_safe_execution_manifests_version_format CHECK (manifest_version ~ '^v[0-9]+\.[0-9]+\.[0-9]+$'),
    CONSTRAINT defense_safe_execution_manifests_engine_check CHECK (engine = 'litesvm'),
    CONSTRAINT defense_safe_execution_manifests_fixtures_object CHECK (jsonb_typeof(fixture_hashes) = 'object'),
    CONSTRAINT defense_safe_execution_manifests_arguments_object CHECK (jsonb_typeof(argument_hashes) = 'object'),
    CONSTRAINT defense_safe_execution_manifests_invariants_array CHECK (jsonb_typeof(invariant_refs) = 'array'),
    CONSTRAINT defense_safe_execution_manifests_budgets_object CHECK (jsonb_typeof(execution_budgets) = 'object'),
    CONSTRAINT defense_safe_execution_manifests_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_safe_execution_manifests_hash_format CHECK (manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_safe_execution_manifests_non_authoritative CHECK (verdict_authority = false),
    CONSTRAINT defense_safe_execution_manifests_ready_requires_approval CHECK (execution_ready = false OR owner_approved = true)
);

CREATE INDEX IF NOT EXISTS defense_safe_execution_manifests_plan_idx
    ON defense_safe_execution_manifests (plan_ref, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_safe_execution_manifests_policy_idx
    ON defense_safe_execution_manifests (policy_ref, created_at DESC);

ALTER TABLE defense_toolchain_attestations
    DROP CONSTRAINT IF EXISTS defense_toolchain_attestations_tool_check;
ALTER TABLE defense_toolchain_attestations
    ADD CONSTRAINT defense_toolchain_attestations_tool_check
    CHECK (tool_name IN ('rustc','cargo','solana','anchor','litesvm','trident'));

DROP TRIGGER IF EXISTS defense_toolchain_policies_immutable ON defense_toolchain_policies;
CREATE TRIGGER defense_toolchain_policies_immutable
BEFORE UPDATE OR DELETE ON defense_toolchain_policies
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();

DROP TRIGGER IF EXISTS defense_safe_execution_manifests_immutable ON defense_safe_execution_manifests;
CREATE TRIGGER defense_safe_execution_manifests_immutable
BEFORE UPDATE OR DELETE ON defense_safe_execution_manifests
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();