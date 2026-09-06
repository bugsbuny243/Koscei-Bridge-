CREATE TABLE IF NOT EXISTS defense_source_imports (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    import_ref text NOT NULL UNIQUE,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    repository_url text NOT NULL,
    repository_owner text NOT NULL,
    repository_name text NOT NULL,
    commit_sha text NOT NULL,
    archive_hash text NOT NULL,
    source_artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    file_count integer NOT NULL,
    source_bytes integer NOT NULL,
    skipped_files integer NOT NULL DEFAULT 0,
    status text NOT NULL DEFAULT 'imported',
    evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    import_hash text NOT NULL,
    verdict_authority boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_source_imports_ref_format CHECK (import_ref ~ '^KSI1-[0-9a-f]{32}$'),
    CONSTRAINT defense_source_imports_commit_format CHECK (commit_sha ~ '^[0-9a-f]{40}$'),
    CONSTRAINT defense_source_imports_archive_hash_format CHECK (archive_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_source_imports_import_hash_format CHECK (import_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_source_imports_status_check CHECK (status IN ('imported','partial','failed')),
    CONSTRAINT defense_source_imports_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
    CONSTRAINT defense_source_imports_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_source_imports_counts_check CHECK (file_count > 0 AND source_bytes > 0 AND skipped_files >= 0),
    CONSTRAINT defense_source_imports_nonempty CHECK (
        btrim(program_id) <> '' AND btrim(network) <> '' AND btrim(repository_url) <> '' AND
        btrim(repository_owner) <> '' AND btrim(repository_name) <> ''
    ),
    CONSTRAINT defense_source_imports_non_authoritative CHECK (verdict_authority = false)
);

CREATE INDEX IF NOT EXISTS defense_source_imports_program_created_idx
    ON defense_source_imports (program_id, network, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_source_imports_repository_commit_idx
    ON defense_source_imports (repository_owner, repository_name, commit_sha);
CREATE INDEX IF NOT EXISTS defense_source_imports_artifact_idx
    ON defense_source_imports (source_artifact_ref);

DROP TRIGGER IF EXISTS defense_source_imports_immutable ON defense_source_imports;
CREATE TRIGGER defense_source_imports_immutable
BEFORE UPDATE OR DELETE ON defense_source_imports
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
