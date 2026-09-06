CREATE TABLE IF NOT EXISTS defense_benchmark_cases (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    case_ref text NOT NULL UNIQUE,
    name text NOT NULL,
    category text NOT NULL,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    source_artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    expected_rules jsonb NOT NULL DEFAULT '[]'::jsonb,
    expected_absent_rules jsonb NOT NULL DEFAULT '[]'::jsonb,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_by text NOT NULL DEFAULT 'owner',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_benchmark_cases_ref_format CHECK (case_ref ~ '^KBC1-[0-9a-f]{32}$'),
    CONSTRAINT defense_benchmark_cases_category_check CHECK (category IN ('source_audit','binary_audit','false_positive','reproduction','patch_verification','onchain_investigation','evidence_discipline')),
    CONSTRAINT defense_benchmark_cases_expected_array CHECK (jsonb_typeof(expected_rules) = 'array'),
    CONSTRAINT defense_benchmark_cases_absent_array CHECK (jsonb_typeof(expected_absent_rules) = 'array'),
    CONSTRAINT defense_benchmark_cases_metadata_object CHECK (jsonb_typeof(metadata) = 'object'),
    CONSTRAINT defense_benchmark_cases_nonempty CHECK (btrim(name) <> '' AND btrim(program_id) <> '')
);

CREATE TABLE IF NOT EXISTS defense_evaluation_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    evaluation_ref text NOT NULL UNIQUE,
    benchmark_case_ref text NOT NULL REFERENCES defense_benchmark_cases(case_ref) ON DELETE RESTRICT,
    detector_version text NOT NULL,
    observed_rules jsonb NOT NULL DEFAULT '[]'::jsonb,
    metrics jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL,
    result_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_evaluation_runs_ref_format CHECK (evaluation_ref ~ '^KEV1-[0-9a-f]{32}$'),
    CONSTRAINT defense_evaluation_runs_rules_array CHECK (jsonb_typeof(observed_rules) = 'array'),
    CONSTRAINT defense_evaluation_runs_metrics_object CHECK (jsonb_typeof(metrics) = 'object'),
    CONSTRAINT defense_evaluation_runs_status_check CHECK (status IN ('passed','failed','partial','blocked')),
    CONSTRAINT defense_evaluation_runs_hash_format CHECK (result_hash ~ '^sha256:[0-9a-f]{64}$')
);

CREATE TABLE IF NOT EXISTS defense_training_examples (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    example_ref text NOT NULL UNIQUE,
    source_kind text NOT NULL,
    program_id text NOT NULL,
    input_json jsonb NOT NULL,
    output_json jsonb NOT NULL,
    provenance_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    quality_status text NOT NULL DEFAULT 'candidate',
    example_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_training_examples_ref_format CHECK (example_ref ~ '^KTE1-[0-9a-f]{32}$'),
    CONSTRAINT defense_training_examples_source_check CHECK (source_kind IN ('verified_finding','proof_of_fix','hard_negative','synthetic_mutation','human_reviewed_trajectory')),
    CONSTRAINT defense_training_examples_input_object CHECK (jsonb_typeof(input_json) = 'object'),
    CONSTRAINT defense_training_examples_output_object CHECK (jsonb_typeof(output_json) = 'object'),
    CONSTRAINT defense_training_examples_provenance_array CHECK (jsonb_typeof(provenance_refs) = 'array'),
    CONSTRAINT defense_training_examples_quality_check CHECK (quality_status IN ('candidate','human_reviewed','benchmark_passed','rejected')),
    CONSTRAINT defense_training_examples_hash_format CHECK (example_hash ~ '^sha256:[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS defense_benchmark_cases_category_idx ON defense_benchmark_cases (category, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_evaluation_runs_case_idx ON defense_evaluation_runs (benchmark_case_ref, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_training_examples_program_idx ON defense_training_examples (program_id, created_at DESC);

DROP TRIGGER IF EXISTS defense_benchmark_cases_immutable ON defense_benchmark_cases;
CREATE TRIGGER defense_benchmark_cases_immutable BEFORE UPDATE OR DELETE ON defense_benchmark_cases
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
DROP TRIGGER IF EXISTS defense_evaluation_runs_immutable ON defense_evaluation_runs;
CREATE TRIGGER defense_evaluation_runs_immutable BEFORE UPDATE OR DELETE ON defense_evaluation_runs
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
DROP TRIGGER IF EXISTS defense_training_examples_immutable ON defense_training_examples;
CREATE TRIGGER defense_training_examples_immutable BEFORE UPDATE OR DELETE ON defense_training_examples
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();