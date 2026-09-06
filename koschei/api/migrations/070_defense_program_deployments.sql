CREATE TABLE IF NOT EXISTS defense_program_deployments (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_ref text NOT NULL UNIQUE,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    loader_id text NOT NULL,
    loader_kind text NOT NULL,
    programdata_address text,
    account_slot bigint NOT NULL,
    deployment_slot bigint,
    upgrade_authority text,
    upgrade_authority_open boolean NOT NULL DEFAULT false,
    executable boolean NOT NULL DEFAULT false,
    full_binary_hash text NOT NULL,
    canonical_binary_hash text NOT NULL,
    full_binary_size integer NOT NULL,
    canonical_binary_size integer NOT NULL,
    trailing_zero_bytes integer NOT NULL DEFAULT 0,
    binary_artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    manifest_artifact_ref text REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    source_commit text,
    match_status text NOT NULL DEFAULT 'not_requested',
    match_evidence_status text NOT NULL DEFAULT 'not_evaluated',
    evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    snapshot_hash text NOT NULL,
    verdict_authority boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_program_deployments_ref_format CHECK (snapshot_ref ~ '^KDS1-[0-9a-f]{32}$'),
    CONSTRAINT defense_program_deployments_loader_kind_check CHECK (loader_kind IN ('bpf_upgradeable_loader','bpf_loader_v2','bpf_loader_v1')),
    CONSTRAINT defense_program_deployments_hash_format CHECK (
        full_binary_hash ~ '^sha256:[0-9a-f]{64}$' AND
        canonical_binary_hash ~ '^sha256:[0-9a-f]{64}$' AND
        snapshot_hash ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT defense_program_deployments_size_check CHECK (
        full_binary_size > 0 AND canonical_binary_size > 0 AND
        canonical_binary_size <= full_binary_size AND trailing_zero_bytes >= 0
    ),
    CONSTRAINT defense_program_deployments_match_status_check CHECK (match_status IN (
        'not_requested','invalid_manifest','matched_full_binary','matched_after_zero_padding_normalization','mismatched'
    )),
    CONSTRAINT defense_program_deployments_evidence_status_check CHECK (match_evidence_status IN (
        'not_evaluated','insufficient','observed','contradicted'
    )),
    CONSTRAINT defense_program_deployments_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
    CONSTRAINT defense_program_deployments_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_program_deployments_nonempty CHECK (
        btrim(program_id) <> '' AND btrim(network) <> '' AND btrim(loader_id) <> '' AND account_slot >= 0
    ),
    CONSTRAINT defense_program_deployments_authority_consistency CHECK (
        upgrade_authority_open = (upgrade_authority IS NOT NULL AND btrim(upgrade_authority) <> '')
    ),
    CONSTRAINT defense_program_deployments_non_authoritative CHECK (verdict_authority = false)
);

CREATE INDEX IF NOT EXISTS defense_program_deployments_program_created_idx
    ON defense_program_deployments (program_id, network, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_program_deployments_binary_hash_idx
    ON defense_program_deployments (canonical_binary_hash, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_program_deployments_upgrade_authority_idx
    ON defense_program_deployments (upgrade_authority, created_at DESC)
    WHERE upgrade_authority IS NOT NULL;

DROP TRIGGER IF EXISTS defense_program_deployments_immutable ON defense_program_deployments;
CREATE TRIGGER defense_program_deployments_immutable
BEFORE UPDATE OR DELETE ON defense_program_deployments
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
