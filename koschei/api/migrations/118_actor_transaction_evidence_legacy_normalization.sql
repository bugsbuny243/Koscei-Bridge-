-- Follow-up repair for 081_actor_transaction_evidence_idempotency.sql.
--
-- Migration 081 installed the steady-state idempotency trigger before its
-- historical normalization UPDATE. That trigger correctly preserves the old
-- occurrence_count for immutable transaction evidence, but it also prevented
-- the one-time repair from changing legacy inflated rows back to 1.
--
-- Keep the repair narrowly scoped to immutable transaction evidence. Snapshot
-- and event evidence intentionally use occurrence_count as a recurrence signal.

-- Seed a temporary legacy-shaped row so this migration proves that the repair
-- path actually changes an inflated immutable observation back to one.
DELETE FROM security_actor_evidence
WHERE network = 'solana-mainnet'
  AND actor_wallet = '__koschei_legacy_normalization_probe_actor__'
  AND evidence_key = '__koschei_legacy_normalization_probe_signature__:0';

INSERT INTO security_actor_evidence (
    network, actor_wallet, counterpart_kind, counterpart_id, relation,
    verification_status, evidence_key, source, signature, slot,
    observed_at, occurrence_count, metadata
) VALUES (
    'solana-mainnet', '__koschei_legacy_normalization_probe_actor__', 'wallet',
    '__koschei_legacy_normalization_probe_counterpart__', 'direct_sol_transfer_out',
    'observed', '__koschei_legacy_normalization_probe_signature__:0',
    'solana_jsonparsed_instruction', '__koschei_legacy_normalization_probe_signature__',
    1, to_timestamp(1), 7,
    '{"program":"system","source_wallet":"__koschei_legacy_normalization_probe_actor__","destination_wallet":"__koschei_legacy_normalization_probe_counterpart__"}'::jsonb
);

-- Disable only the transaction-evidence count preservation trigger while the
-- historical repair runs. The migration runner executes this whole file in one
-- PostgreSQL transaction, so any failure rolls the trigger state back as well.
DROP TRIGGER IF EXISTS zz_security_actor_transaction_evidence_idempotency
    ON security_actor_evidence;

UPDATE security_actor_evidence
SET occurrence_count = 1,
    updated_at = now()
WHERE source IN ('solana_jsonparsed_instruction', 'solana_transaction_logs')
  AND occurrence_count <> 1;

-- Prove the legacy repair before restoring steady-state protection.
DO $$
DECLARE
    probe_count bigint;
BEGIN
    IF EXISTS (
        SELECT 1
        FROM security_actor_evidence
        WHERE source IN ('solana_jsonparsed_instruction', 'solana_transaction_logs')
          AND occurrence_count <> 1
    ) THEN
        RAISE EXCEPTION 'transaction evidence legacy normalization failed: immutable occurrence_count must equal 1';
    END IF;

    SELECT occurrence_count INTO probe_count
    FROM security_actor_evidence
    WHERE network = 'solana-mainnet'
      AND actor_wallet = '__koschei_legacy_normalization_probe_actor__'
      AND evidence_key = '__koschei_legacy_normalization_probe_signature__:0';

    IF probe_count IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'transaction evidence legacy normalization probe failed: occurrence_count=%', probe_count;
    END IF;
END;
$$;

-- Reinstall the canonical steady-state invariant from migration 081.
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

CREATE TRIGGER zz_security_actor_transaction_evidence_idempotency
BEFORE UPDATE ON security_actor_evidence
FOR EACH ROW
EXECUTE FUNCTION preserve_security_actor_transaction_evidence_count();

-- Prove that a repeated read/upsert still cannot manufacture recurrence after
-- the historical repair has completed and the trigger is restored.
INSERT INTO security_actor_evidence (
    network, actor_wallet, counterpart_kind, counterpart_id, relation,
    verification_status, evidence_key, source, signature, slot,
    observed_at, occurrence_count, metadata
) VALUES (
    'solana-mainnet', '__koschei_legacy_normalization_probe_actor__', 'wallet',
    '__koschei_legacy_normalization_probe_counterpart__', 'direct_sol_transfer_out',
    'observed', '__koschei_legacy_normalization_probe_signature__:0',
    'solana_jsonparsed_instruction', '__koschei_legacy_normalization_probe_signature__',
    1, to_timestamp(1), 1,
    '{"program":"system","source_wallet":"__koschei_legacy_normalization_probe_actor__","destination_wallet":"__koschei_legacy_normalization_probe_counterpart__"}'::jsonb
)
ON CONFLICT (network,actor_wallet,counterpart_kind,counterpart_id,relation,source,evidence_key)
DO UPDATE SET
    occurrence_count = security_actor_evidence.occurrence_count + 1,
    updated_at = now();

DO $$
DECLARE
    invariant_count bigint;
BEGIN
    SELECT occurrence_count INTO invariant_count
    FROM security_actor_evidence
    WHERE network = 'solana-mainnet'
      AND actor_wallet = '__koschei_legacy_normalization_probe_actor__'
      AND evidence_key = '__koschei_legacy_normalization_probe_signature__:0';

    IF invariant_count IS DISTINCT FROM 1 THEN
        RAISE EXCEPTION 'transaction evidence idempotency invariant failed after legacy repair: occurrence_count=%', invariant_count;
    END IF;
END;
$$;

DELETE FROM security_actor_evidence
WHERE network = 'solana-mainnet'
  AND actor_wallet = '__koschei_legacy_normalization_probe_actor__'
  AND evidence_key = '__koschei_legacy_normalization_probe_signature__:0';
