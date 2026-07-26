-- Customer/API ownership for immutable Defense OS artifacts. Artifacts are
-- content-addressed and may be identical across accounts, so ownership cannot
-- rely on the single defense_program_artifacts.created_by column.

CREATE TABLE IF NOT EXISTS defense_artifact_subscriptions (
    artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    auth_subject text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (artifact_ref, auth_subject),
    CONSTRAINT defense_artifact_subscriptions_subject_nonempty CHECK (btrim(auth_subject) <> '')
);

CREATE INDEX IF NOT EXISTS defense_artifact_subscriptions_subject_created_idx
    ON defense_artifact_subscriptions (auth_subject, created_at DESC, artifact_ref);

CREATE TABLE IF NOT EXISTS defense_lab_runs (
    run_ref text PRIMARY KEY,
    artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    auth_subject text NOT NULL,
    detector_version text NOT NULL,
    decision text NOT NULL,
    finding_count integer NOT NULL DEFAULT 0,
    critical_count integer NOT NULL DEFAULT 0,
    high_count integer NOT NULL DEFAULT 0,
    medium_count integer NOT NULL DEFAULT 0,
    low_count integer NOT NULL DEFAULT 0,
    report_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_lab_runs_ref_check CHECK (run_ref ~ '^KDLR1-[0-9a-f]{32}$'),
    CONSTRAINT defense_lab_runs_subject_nonempty CHECK (btrim(auth_subject) <> ''),
    CONSTRAINT defense_lab_runs_decision_check CHECK (decision IN ('block','warn','review','no_static_trigger')),
    CONSTRAINT defense_lab_runs_counts_check CHECK (
        finding_count >= 0 AND critical_count >= 0 AND high_count >= 0 AND medium_count >= 0 AND low_count >= 0 AND
        finding_count = critical_count + high_count + medium_count + low_count
    ),
    CONSTRAINT defense_lab_runs_hash_check CHECK (report_hash ~ '^sha256:[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS defense_lab_runs_subject_created_idx
    ON defense_lab_runs (auth_subject, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_lab_runs_artifact_created_idx
    ON defense_lab_runs (artifact_ref, created_at DESC);

CREATE OR REPLACE FUNCTION reject_defense_lab_run_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'defense lab runs are immutable';
END;
$$;

DROP TRIGGER IF EXISTS defense_lab_runs_immutable ON defense_lab_runs;
CREATE TRIGGER defense_lab_runs_immutable
BEFORE UPDATE OR DELETE ON defense_lab_runs
FOR EACH ROW EXECUTE FUNCTION reject_defense_lab_run_mutation();
