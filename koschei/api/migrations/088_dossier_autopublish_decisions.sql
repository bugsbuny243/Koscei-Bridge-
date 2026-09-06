-- Immutable autopublish decision ledger.
-- Every policy evaluation is retained, including withheld decisions. Thresholds
-- are fingerprinted into policy_version, so changing a gate creates a new,
-- replayable decision identity instead of silently reusing an old outcome.

CREATE TABLE IF NOT EXISTS dossier_autopublish_decisions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_ref text NOT NULL REFERENCES dossier_exports(case_ref) ON DELETE RESTRICT,
    policy_version text NOT NULL,
    bundle_hash text NOT NULL,
    published boolean NOT NULL,
    reasons jsonb NOT NULL DEFAULT '[]'::jsonb,
    counts jsonb NOT NULL DEFAULT '{}'::jsonb,
    thresholds jsonb NOT NULL DEFAULT '{}'::jsonb,
    decided_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT dossier_autopublish_decisions_case_policy_unique UNIQUE (case_ref, policy_version),
    CONSTRAINT dossier_autopublish_decisions_hash_format CHECK (bundle_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT dossier_autopublish_decisions_version_nonempty CHECK (btrim(policy_version) <> ''),
    CONSTRAINT dossier_autopublish_decisions_reasons_array CHECK (jsonb_typeof(reasons) = 'array'),
    CONSTRAINT dossier_autopublish_decisions_counts_object CHECK (jsonb_typeof(counts) = 'object'),
    CONSTRAINT dossier_autopublish_decisions_thresholds_object CHECK (jsonb_typeof(thresholds) = 'object'),
    CONSTRAINT dossier_autopublish_decisions_reason_contract CHECK (
        (published AND jsonb_array_length(reasons) = 0)
        OR
        (NOT published AND jsonb_array_length(reasons) > 0)
    )
);

CREATE INDEX IF NOT EXISTS dossier_autopublish_decisions_time_idx
    ON dossier_autopublish_decisions (decided_at DESC);

CREATE INDEX IF NOT EXISTS dossier_autopublish_decisions_withheld_idx
    ON dossier_autopublish_decisions (decided_at DESC)
    WHERE NOT published;

CREATE OR REPLACE FUNCTION reject_autopublish_decision_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'autopublish decisions are immutable';
END;
$$;

DROP TRIGGER IF EXISTS dossier_autopublish_decisions_immutable ON dossier_autopublish_decisions;
CREATE TRIGGER dossier_autopublish_decisions_immutable
BEFORE UPDATE OR DELETE ON dossier_autopublish_decisions
FOR EACH ROW EXECUTE FUNCTION reject_autopublish_decision_mutation();
