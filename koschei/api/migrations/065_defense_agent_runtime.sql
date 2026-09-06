CREATE TABLE IF NOT EXISTS defense_agent_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_ref text NOT NULL UNIQUE,
    target text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    execution_mode text NOT NULL DEFAULT 'shadow',
    runtime_version text NOT NULL,
    status text NOT NULL,
    verdict_authority boolean NOT NULL DEFAULT false,
    input_hash text NOT NULL,
    report_hash text NOT NULL,
    report_json jsonb NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_agent_runs_case_ref_format CHECK (case_ref ~ '^KAR1-[0-9a-f]{32}$'),
    CONSTRAINT defense_agent_runs_mode_check CHECK (execution_mode IN ('disabled','shadow')),
    CONSTRAINT defense_agent_runs_status_check CHECK (status IN ('disabled','observed','evidence_pending','partial','blocked')),
    CONSTRAINT defense_agent_runs_no_verdict_authority CHECK (verdict_authority = false),
    CONSTRAINT defense_agent_runs_input_hash_format CHECK (input_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_agent_runs_report_hash_format CHECK (report_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_agent_runs_report_object CHECK (jsonb_typeof(report_json) = 'object'),
    CONSTRAINT defense_agent_runs_nonempty CHECK (btrim(target) <> '' AND btrim(network) <> '' AND btrim(runtime_version) <> '')
);

CREATE INDEX IF NOT EXISTS defense_agent_runs_target_created_idx
    ON defense_agent_runs (target, created_at DESC);

CREATE TABLE IF NOT EXISTS defense_tool_invocations (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    agent_run_id uuid NOT NULL REFERENCES defense_agent_runs(id) ON DELETE RESTRICT,
    tool_run_id text NOT NULL UNIQUE,
    agent_role text NOT NULL,
    tool_name text NOT NULL,
    status text NOT NULL,
    input_hash text NOT NULL,
    output_hash text NOT NULL,
    input_json jsonb NOT NULL,
    output_json jsonb NOT NULL,
    evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    started_at timestamptz NOT NULL,
    finished_at timestamptz NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_tool_invocations_id_format CHECK (tool_run_id ~ '^KTR1-[0-9a-f]{32}$'),
    CONSTRAINT defense_tool_invocations_status_check CHECK (status IN ('observed','evidence_pending','not_applicable','failed')),
    CONSTRAINT defense_tool_invocations_input_hash_format CHECK (input_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_tool_invocations_output_hash_format CHECK (output_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_tool_invocations_input_object CHECK (jsonb_typeof(input_json) = 'object'),
    CONSTRAINT defense_tool_invocations_output_object CHECK (jsonb_typeof(output_json) = 'object'),
    CONSTRAINT defense_tool_invocations_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
    CONSTRAINT defense_tool_invocations_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_tool_invocations_time_order CHECK (finished_at >= started_at),
    CONSTRAINT defense_tool_invocations_nonempty CHECK (btrim(agent_role) <> '' AND btrim(tool_name) <> '')
);

CREATE INDEX IF NOT EXISTS defense_tool_invocations_run_created_idx
    ON defense_tool_invocations (agent_run_id, created_at ASC);

CREATE OR REPLACE FUNCTION reject_defense_runtime_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'immutable defense runtime records cannot be updated or deleted';
END;
$$;

DROP TRIGGER IF EXISTS defense_agent_runs_immutable ON defense_agent_runs;
CREATE TRIGGER defense_agent_runs_immutable
BEFORE UPDATE OR DELETE ON defense_agent_runs
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();

DROP TRIGGER IF EXISTS defense_tool_invocations_immutable ON defense_tool_invocations;
CREATE TRIGGER defense_tool_invocations_immutable
BEFORE UPDATE OR DELETE ON defense_tool_invocations
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
