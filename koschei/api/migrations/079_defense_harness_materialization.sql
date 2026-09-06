CREATE TABLE IF NOT EXISTS defense_harness_materializations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    materialization_ref text NOT NULL UNIQUE,
    materialization_version text NOT NULL,
    profile_ref text NOT NULL REFERENCES defense_harness_execution_profiles(profile_ref) ON DELETE RESTRICT,
    source_harness_artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    materialized_artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    program_id text NOT NULL,
    network text NOT NULL,
    engine text NOT NULL,
    status text NOT NULL,
    file_manifest jsonb NOT NULL DEFAULT '[]'::jsonb,
    file_count integer NOT NULL,
    total_bytes integer NOT NULL,
    cargo_manifest_hash text NOT NULL,
    cargo_lock_hash text NOT NULL,
    materialized_bundle_hash text NOT NULL,
    evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    network_access boolean NOT NULL DEFAULT false,
    dependency_resolution boolean NOT NULL DEFAULT false,
    source_executed boolean NOT NULL DEFAULT false,
    harness_executed boolean NOT NULL DEFAULT false,
    mainnet_transaction_sent boolean NOT NULL DEFAULT false,
    materialization_hash text NOT NULL,
    verdict_authority boolean NOT NULL DEFAULT false,
    created_by text NOT NULL DEFAULT 'owner',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_harness_materializations_ref_format CHECK (materialization_ref ~ '^KHM1-[0-9a-f]{32}$'),
    CONSTRAINT defense_harness_materializations_version_format CHECK (materialization_version ~ '^v[0-9]+\.[0-9]+\.[0-9]+$'),
    CONSTRAINT defense_harness_materializations_engine_check CHECK (engine = 'litesvm'),
    CONSTRAINT defense_harness_materializations_status_check CHECK (status = 'ready'),
    CONSTRAINT defense_harness_materializations_manifest_array CHECK (jsonb_typeof(file_manifest) = 'array'),
    CONSTRAINT defense_harness_materializations_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
    CONSTRAINT defense_harness_materializations_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_harness_materializations_counts_check CHECK (file_count > 0 AND total_bytes > 0 AND total_bytes <= 921600),
    CONSTRAINT defense_harness_materializations_cargo_manifest_hash_format CHECK (cargo_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_harness_materializations_cargo_lock_hash_format CHECK (cargo_lock_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_harness_materializations_bundle_hash_format CHECK (materialized_bundle_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_harness_materializations_hash_format CHECK (materialization_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_harness_materializations_no_network CHECK (network_access = false AND dependency_resolution = false),
    CONSTRAINT defense_harness_materializations_no_execution CHECK (source_executed = false AND harness_executed = false AND mainnet_transaction_sent = false),
    CONSTRAINT defense_harness_materializations_non_authoritative CHECK (verdict_authority = false),
    CONSTRAINT defense_harness_materializations_nonempty CHECK (btrim(program_id) <> '' AND btrim(network) <> '')
);

CREATE INDEX IF NOT EXISTS defense_harness_materializations_profile_idx
    ON defense_harness_materializations (profile_ref, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_harness_materializations_program_idx
    ON defense_harness_materializations (program_id, network, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_harness_materializations_artifact_idx
    ON defense_harness_materializations (materialized_artifact_ref, created_at DESC);

DROP TRIGGER IF EXISTS defense_harness_materializations_immutable ON defense_harness_materializations;
CREATE TRIGGER defense_harness_materializations_immutable
BEFORE UPDATE OR DELETE ON defense_harness_materializations
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
