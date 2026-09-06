CREATE TABLE IF NOT EXISTS defense_program_artifacts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    artifact_ref text NOT NULL UNIQUE,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    artifact_type text NOT NULL,
    source_uri text,
    source_commit text,
    framework text,
    framework_version text,
    runtime_version text,
    content_hash text NOT NULL,
    content_encoding text NOT NULL DEFAULT 'utf8',
    content_bytes bytea NOT NULL,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    trust_level text NOT NULL DEFAULT 'unverified',
    verified boolean NOT NULL DEFAULT false,
    created_by text NOT NULL DEFAULT 'owner',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_program_artifacts_ref_format CHECK (artifact_ref ~ '^KDA1-[0-9a-f]{32}$'),
    CONSTRAINT defense_program_artifacts_type_check CHECK (artifact_type IN ('source_bundle','source_manifest','anchor_idl','sbpf_bytecode','sbpf_manifest','knowledge_document','synthetic_source_bundle')),
    CONSTRAINT defense_program_artifacts_encoding_check CHECK (content_encoding IN ('utf8','json','base64','manifest')),
    CONSTRAINT defense_program_artifacts_hash_format CHECK (content_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_program_artifacts_trust_check CHECK (trust_level IN ('verified','observed','unverified','synthetic')),
    CONSTRAINT defense_program_artifacts_metadata_object CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT defense_program_artifacts_nonempty CHECK (btrim(program_id) <> '' AND btrim(network) <> '' AND octet_length(content_bytes) > 0),
    CONSTRAINT defense_program_artifacts_verified_consistency CHECK (verified = false OR trust_level = 'verified')
);

CREATE INDEX IF NOT EXISTS defense_program_artifacts_program_created_idx
    ON defense_program_artifacts (program_id, network, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_program_artifacts_type_created_idx
    ON defense_program_artifacts (artifact_type, created_at DESC);

CREATE TABLE IF NOT EXISTS defense_knowledge_documents (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    document_ref text NOT NULL UNIQUE,
    title text NOT NULL,
    body text NOT NULL,
    source_uri text,
    source_commit text,
    source_hash text NOT NULL,
    framework text,
    framework_version text,
    runtime_version text,
    valid_from timestamptz,
    valid_to timestamptz,
    trust_level text NOT NULL DEFAULT 'observed',
    tags jsonb NOT NULL DEFAULT '[]'::jsonb,
    embedding_model text,
    embedding double precision[],
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by text NOT NULL DEFAULT 'owner',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_knowledge_documents_ref_format CHECK (document_ref ~ '^KDK1-[0-9a-f]{32}$'),
    CONSTRAINT defense_knowledge_documents_hash_format CHECK (source_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_knowledge_documents_trust_check CHECK (trust_level IN ('verified','observed','unverified','synthetic')),
    CONSTRAINT defense_knowledge_documents_tags_array CHECK (jsonb_typeof(tags) = 'array'),
    CONSTRAINT defense_knowledge_documents_metadata_object CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT defense_knowledge_documents_nonempty CHECK (btrim(title) <> '' AND btrim(body) <> ''),
    CONSTRAINT defense_knowledge_documents_validity CHECK (valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from)
);

CREATE INDEX IF NOT EXISTS defense_knowledge_documents_created_idx
    ON defense_knowledge_documents (created_at DESC);
CREATE INDEX IF NOT EXISTS defense_knowledge_documents_framework_idx
    ON defense_knowledge_documents (framework, framework_version, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_knowledge_documents_search_idx
    ON defense_knowledge_documents USING gin (to_tsvector('simple', title || ' ' || body));

DROP TRIGGER IF EXISTS defense_program_artifacts_immutable ON defense_program_artifacts;
CREATE TRIGGER defense_program_artifacts_immutable
BEFORE UPDATE OR DELETE ON defense_program_artifacts
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();

DROP TRIGGER IF EXISTS defense_knowledge_documents_immutable ON defense_knowledge_documents;
CREATE TRIGGER defense_knowledge_documents_immutable
BEFORE UPDATE OR DELETE ON defense_knowledge_documents
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();