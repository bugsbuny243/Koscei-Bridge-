-- Canonical architecture: ACTOR_INVESTIGATION_ENGINE.md sections 3, 4 and 6.
-- A transaction evidence_key identifies one immutable chain observation
-- (normally signature + instruction index). Re-reading that same transaction
-- must refresh metadata/verification but must not manufacture another occurrence.

CREATE OR REPLACE FUNCTION preserve_security_actor_transaction_evidence_count()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF OLD.source IN ('solana_jsonparsed_instruction', 'solana_transaction_logs')
       AND NEW.source = OLD.source
       AND NEW.evidence_key = OLD.evidence_key THEN
        NEW.occurrence_count := OLD.occurrence_count;
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS zz_security_actor_transaction_evidence_idempotency
    ON security_actor_evidence;
CREATE TRIGGER zz_security_actor_transaction_evidence_idempotency
BEFORE UPDATE ON security_actor_evidence
FOR EACH ROW
EXECUTE FUNCTION preserve_security_actor_transaction_evidence_count();

-- Earlier live rescans incremented immutable transaction rows on every pass.
-- One evidence_key is one chain observation, so normalize those historical rows.
UPDATE security_actor_evidence
SET occurrence_count = 1,
    updated_at = now()
WHERE source IN ('solana_jsonparsed_instruction', 'solana_transaction_logs')
  AND occurrence_count <> 1;

-- Fail the migration if PostgreSQL does not preserve one immutable observation.
-- The temporary row is deleted before this block exits successfully.
DO $$
DECLARE
    invariant_count bigint;
BEGIN
    INSERT INTO security_actor_evidence (
        network, actor_wallet, counterpart_kind, counterpart_id, relation,
        verification_status, evidence_key, source, signature, slot,
        observed_at, occurrence_count, metadata
    ) VALUES (
        'solana-mainnet', '__koschei_idempotency_probe_actor__', 'wallet',
        '__koschei_idempotency_probe_counterpart__', 'direct_sol_transfer_out',
        'observed', '__koschei_idempotency_probe_signature__:0',
        'solana_jsonparsed_instruction', '__koschei_idempotency_probe_signature__',
        1, to_timestamp(1), 1,
        '{"program":"system","source_wallet":"__koschei_idempotency_probe_actor__","destination_wallet":"__koschei_idempotency_probe_counterpart__"}'::jsonb
    );

    INSERT INTO security_actor_evidence (
        network, actor_wallet, counterpart_kind, counterpart_id, relation,
        verification_status, evidence_key, source, signature, slot,
        observed_at, occurrence_count, metadata
    ) VALUES (
        'solana-mainnet', '__koschei_idempotency_probe_actor__', 'wallet',
        '__koschei_idempotency_probe_counterpart__', 'direct_sol_transfer_out',
        'observed', '__koschei_idempotency_probe_signature__:0',
        'solana_jsonparsed_instruction', '__koschei_idempotency_probe_signature__',
        1, to_timestamp(1), 1,
        '{"program":"system","source_wallet":"__koschei_idempotency_probe_actor__","destination_wallet":"__koschei_idempotency_probe_counterpart__"}'::jsonb
    )
    ON CONFLICT (network,actor_wallet,counterpart_kind,counterpart_id,relation,source,evidence_key)
    DO UPDATE SET
        occurrence_count = security_actor_evidence.occurrence_count + 1,
        updated_at = now();

    SELECT occurrence_count INTO invariant_count
    FROM security_actor_evidence
    WHERE network = 'solana-mainnet'
      AND actor_wallet = '__koschei_idempotency_probe_actor__'
      AND evidence_key = '__koschei_idempotency_probe_signature__:0';

    IF invariant_count IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'transaction evidence idempotency invariant failed: occurrence_count=%', invariant_count;
    END IF;

    DELETE FROM security_actor_evidence
    WHERE network = 'solana-mainnet'
      AND actor_wallet = '__koschei_idempotency_probe_actor__'
      AND evidence_key = '__koschei_idempotency_probe_signature__:0';
END;
$$;
