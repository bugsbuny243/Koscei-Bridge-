-- Query support for Actor Operational Memory v1.
-- The matcher joins persistent evidence by counterpart + relation while keeping
-- actor-wallet and verification filters bounded. Partial indexes avoid paying
-- for inferred/unverified rows that are never eligible for operational matches.
CREATE INDEX IF NOT EXISTS idx_security_actor_evidence_operational_counterpart
    ON public.security_actor_evidence
       (network,counterpart_kind,counterpart_id,relation,actor_wallet)
    WHERE verification_status IN ('verified','observed');

CREATE INDEX IF NOT EXISTS idx_security_actor_evidence_operational_actor
    ON public.security_actor_evidence
       (network,actor_wallet,counterpart_kind,relation,counterpart_id)
    WHERE verification_status IN ('verified','observed');
