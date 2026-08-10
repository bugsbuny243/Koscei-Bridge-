-- Koschei verified incident corpus v1.
--
-- This is a durable, append-only memory of a strict evidence conjunction:
--   1) a VERIFIED actor-linked exit/security event with a real signature + slot;
--   2) a Koschei-signed material final verdict for the same token/network.
--
-- A corpus row records that both facts were observed. It does NOT assert that
-- the actor caused the token verdict, that multiple wallets are one real person,
-- or that a historical actor is malicious in every future transaction.

CREATE TABLE IF NOT EXISTS public.security_incident_corpus (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    incident_key text NOT NULL UNIQUE,
    schema_version text NOT NULL DEFAULT 'koschei-incident-corpus-v1',
    network text NOT NULL DEFAULT 'solana-mainnet',
    target text NOT NULL,
    actor_wallet text NOT NULL,
    event_kind text NOT NULL,
    source_rule_id text NOT NULL,
    event_signature text NOT NULL,
    event_slot bigint NOT NULL,
    event_observed_at timestamptz NOT NULL,
    verdict_id uuid NOT NULL,
    verdict_signature text NOT NULL,
    verdict_updated_at timestamptz NOT NULL,
    verdict_rule_version text NOT NULL,
    grade text NOT NULL DEFAULT '',
    risk_index integer NOT NULL,
    risk_level text NOT NULL,
    verdict text NOT NULL DEFAULT '',
    recommendation text NOT NULL DEFAULT '',
    evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    signals jsonb NOT NULL DEFAULT '{}'::jsonb,
    verdict_source text NOT NULL DEFAULT '',
    record_hash text NOT NULL,
    supersedes_incident_id uuid REFERENCES public.security_incident_corpus(id),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT security_incident_corpus_identity_check CHECK (
        btrim(incident_key) <> '' AND
        btrim(network) <> '' AND
        btrim(target) <> '' AND
        btrim(actor_wallet) <> '' AND
        btrim(event_kind) <> '' AND
        btrim(source_rule_id) <> '' AND
        btrim(event_signature) <> '' AND
        btrim(verdict_signature) <> '' AND
        btrim(verdict_rule_version) <> ''
    ),
    CONSTRAINT security_incident_corpus_event_reference_check CHECK (
        event_slot > 0 AND event_observed_at <= created_at + interval '5 minutes'
    ),
    CONSTRAINT security_incident_corpus_risk_check CHECK (
        risk_index >= 0 AND risk_index <= 100 AND risk_level IN ('high','critical')
    ),
    CONSTRAINT security_incident_corpus_json_check CHECK (
        jsonb_typeof(evidence) = 'array' AND jsonb_typeof(signals) = 'object'
    ),
    CONSTRAINT security_incident_corpus_hash_check CHECK (
        record_hash ~ '^sha256:[0-9a-f]{64}$'
    ),
    CONSTRAINT security_incident_corpus_key_check CHECK (
        incident_key ~ '^KIC1-[0-9a-f]{64}$'
    )
);

CREATE INDEX IF NOT EXISTS idx_security_incident_corpus_actor
    ON public.security_incident_corpus (network,actor_wallet,created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_incident_corpus_target
    ON public.security_incident_corpus (network,target,created_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_incident_corpus_event
    ON public.security_incident_corpus (network,event_kind,event_observed_at DESC);

CREATE INDEX IF NOT EXISTS idx_security_incident_corpus_risk
    ON public.security_incident_corpus (network,risk_level,risk_index DESC,created_at DESC);

CREATE OR REPLACE FUNCTION public.reject_security_incident_corpus_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'security incident corpus is append-only';
END;
$$;

DROP TRIGGER IF EXISTS security_incident_corpus_immutable ON public.security_incident_corpus;
CREATE TRIGGER security_incident_corpus_immutable
BEFORE UPDATE OR DELETE ON public.security_incident_corpus
FOR EACH ROW EXECUTE FUNCTION public.reject_security_incident_corpus_mutation();
