CREATE TABLE IF NOT EXISTS dossier_source_snapshots (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    mint text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    verdict_id text,
    verdict_signature text NOT NULL,
    ruleset_version text NOT NULL,
    produced_at timestamptz NOT NULL,
    source_hash text NOT NULL,
    canonical_source bytea NOT NULL,
    source_payload jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT dossier_source_snapshots_signature_unique UNIQUE (verdict_signature),
    CONSTRAINT dossier_source_snapshots_hash_format CHECK (source_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT dossier_source_snapshots_payload_object CHECK (jsonb_typeof(source_payload) = 'object'),
    CONSTRAINT dossier_source_snapshots_nonempty CHECK (btrim(mint) <> '' AND btrim(network) <> '' AND btrim(verdict_signature) <> '' AND btrim(ruleset_version) <> '')
);

CREATE INDEX IF NOT EXISTS dossier_source_snapshots_mint_produced_idx
    ON dossier_source_snapshots (mint,produced_at DESC);

CREATE TABLE IF NOT EXISTS dossier_exports (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_ref text NOT NULL UNIQUE,
    mint text NOT NULL,
    verdict_id text,
    verdict_signature text NOT NULL,
    source_snapshot_id uuid NOT NULL REFERENCES dossier_source_snapshots(id) ON DELETE RESTRICT,
    bundle_hash text NOT NULL,
    canonical_bundle bytea NOT NULL,
    bundle_json jsonb NOT NULL,
    requested_by text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT dossier_exports_case_ref_format CHECK (case_ref ~ '^KD1-[a-z2-7]{32}$'),
    CONSTRAINT dossier_exports_hash_format CHECK (bundle_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT dossier_exports_bundle_object CHECK (jsonb_typeof(bundle_json) = 'object'),
    CONSTRAINT dossier_exports_nonempty CHECK (btrim(mint) <> '' AND btrim(verdict_signature) <> '' AND btrim(requested_by) <> '')
);

CREATE INDEX IF NOT EXISTS dossier_exports_mint_created_idx
    ON dossier_exports (mint,created_at DESC);

CREATE OR REPLACE FUNCTION reject_immutable_dossier_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'immutable dossier records cannot be updated or deleted';
END;
$$;

DROP TRIGGER IF EXISTS dossier_source_snapshots_immutable ON dossier_source_snapshots;
CREATE TRIGGER dossier_source_snapshots_immutable
BEFORE UPDATE OR DELETE ON dossier_source_snapshots
FOR EACH ROW EXECUTE FUNCTION reject_immutable_dossier_mutation();

DROP TRIGGER IF EXISTS dossier_exports_immutable ON dossier_exports;
CREATE TRIGGER dossier_exports_immutable
BEFORE UPDATE OR DELETE ON dossier_exports
FOR EACH ROW EXECUTE FUNCTION reject_immutable_dossier_mutation();
