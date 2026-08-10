-- Persistent technical campaign-genome index.
--
-- Pattern hashes intentionally exclude actor counterpart addresses and token
-- mints. A matching pattern therefore means the same normalized technical
-- behavior descriptors were observed; it never proves common real-world
-- identity, common control or wrongdoing across wallet addresses.

CREATE TABLE IF NOT EXISTS public.security_campaign_genome_index (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    snapshot_key text NOT NULL UNIQUE,
    schema_version text NOT NULL DEFAULT 'koschei-campaign-genome-index-v1',
    genome_version text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    actor_wallet text NOT NULL,
    genome_id text NOT NULL,
    pattern_hash_sha256 text NOT NULL,
    evidence_hash_sha256 text NOT NULL,
    descriptor_count integer NOT NULL DEFAULT 0,
    verified_descriptor_count integer NOT NULL DEFAULT 0,
    observed_descriptor_count integer NOT NULL DEFAULT 0,
    verified_signature_backed_count integer NOT NULL DEFAULT 0,
    watch_descriptor_count integer NOT NULL DEFAULT 0,
    descriptors jsonb NOT NULL DEFAULT '[]'::jsonb,
    watch_descriptors jsonb NOT NULL DEFAULT '[]'::jsonb,
    policy jsonb NOT NULL DEFAULT '{}'::jsonb,
    record_hash text NOT NULL,
    observed_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT security_campaign_genome_index_identity_check CHECK (
        btrim(network)<>'' AND btrim(actor_wallet)<>'' AND btrim(genome_id)<>''
        AND btrim(genome_version)<>''
    ),
    CONSTRAINT security_campaign_genome_index_pattern_hash_check CHECK (
        pattern_hash_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT security_campaign_genome_index_evidence_hash_check CHECK (
        evidence_hash_sha256 ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT security_campaign_genome_index_record_hash_check CHECK (
        record_hash ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT security_campaign_genome_index_snapshot_key_check CHECK (
        snapshot_key ~ '^KCGS1-[0-9a-f]{64}$'
    ),
    CONSTRAINT security_campaign_genome_index_json_check CHECK (
        jsonb_typeof(descriptors)='array'
        AND jsonb_typeof(watch_descriptors)='array'
        AND jsonb_typeof(policy)='object'
    ),
    CONSTRAINT security_campaign_genome_index_counts_check CHECK (
        descriptor_count>=0 AND verified_descriptor_count>=0
        AND observed_descriptor_count>=0 AND verified_signature_backed_count>=0
        AND watch_descriptor_count>=0
    )
);

CREATE UNIQUE INDEX IF NOT EXISTS ux_security_campaign_genome_actor_evidence
    ON public.security_campaign_genome_index (network,actor_wallet,evidence_hash_sha256);

CREATE INDEX IF NOT EXISTS idx_security_campaign_genome_pattern
    ON public.security_campaign_genome_index (network,pattern_hash_sha256,created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_campaign_genome_actor
    ON public.security_campaign_genome_index (network,actor_wallet,created_at DESC);

CREATE OR REPLACE FUNCTION public.reject_security_campaign_genome_index_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'security campaign genome index is append-only';
END;
$$;

DROP TRIGGER IF EXISTS security_campaign_genome_index_immutable
    ON public.security_campaign_genome_index;
CREATE TRIGGER security_campaign_genome_index_immutable
BEFORE UPDATE OR DELETE ON public.security_campaign_genome_index
FOR EACH ROW EXECUTE FUNCTION public.reject_security_campaign_genome_index_mutation();
