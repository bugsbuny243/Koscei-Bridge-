CREATE TABLE IF NOT EXISTS defense_verification_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    verification_ref text NOT NULL UNIQUE,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    finding_ref text REFERENCES defense_program_findings(finding_ref) ON DELETE RESTRICT,
    source_artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    patch_ref text,
    execution_mode text NOT NULL DEFAULT 'blocked',
    status text NOT NULL,
    commands jsonb NOT NULL DEFAULT '[]'::jsonb,
    command_results jsonb NOT NULL DEFAULT '[]'::jsonb,
    input_hash text NOT NULL,
    output_hash text NOT NULL,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    can_execute_mainnet boolean NOT NULL DEFAULT false,
    created_by text NOT NULL DEFAULT 'owner',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_verification_runs_ref_format CHECK (verification_ref ~ '^KDV1-[0-9a-f]{32}$'),
    CONSTRAINT defense_verification_runs_mode_check CHECK (execution_mode IN ('blocked','local_sandbox')),
    CONSTRAINT defense_verification_runs_status_check CHECK (status IN ('blocked','passed','failed','partial','tool_unavailable')),
    CONSTRAINT defense_verification_runs_commands_array CHECK (jsonb_typeof(commands) = 'array'),
    CONSTRAINT defense_verification_runs_results_array CHECK (jsonb_typeof(command_results) = 'array'),
    CONSTRAINT defense_verification_runs_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_verification_runs_input_hash_format CHECK (input_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_verification_runs_output_hash_format CHECK (output_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_verification_runs_no_mainnet CHECK (can_execute_mainnet = false),
    CONSTRAINT defense_verification_runs_nonempty CHECK (btrim(program_id) <> '')
);
CREATE INDEX IF NOT EXISTS defense_verification_runs_program_idx
    ON defense_verification_runs (program_id, network, created_at DESC);

CREATE TABLE IF NOT EXISTS defense_patch_proposals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    patch_ref text NOT NULL UNIQUE,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    finding_ref text REFERENCES defense_program_findings(finding_ref) ON DELETE RESTRICT,
    source_artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    provider text,
    model text,
    proposal_json jsonb NOT NULL,
    proposal_hash text NOT NULL,
    human_approved boolean NOT NULL DEFAULT false,
    applied_to_production boolean NOT NULL DEFAULT false,
    created_by text NOT NULL DEFAULT 'owner',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_patch_proposals_ref_format CHECK (patch_ref ~ '^KDP1-[0-9a-f]{32}$'),
    CONSTRAINT defense_patch_proposals_object CHECK (jsonb_typeof(proposal_json) = 'object'),
    CONSTRAINT defense_patch_proposals_hash_format CHECK (proposal_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_patch_proposals_not_production CHECK (applied_to_production = false),
    CONSTRAINT defense_patch_proposals_nonempty CHECK (btrim(program_id) <> '')
);
CREATE INDEX IF NOT EXISTS defense_patch_proposals_program_idx
    ON defense_patch_proposals (program_id, network, created_at DESC);

CREATE TABLE IF NOT EXISTS defense_patch_approvals (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    approval_ref text NOT NULL UNIQUE,
    patch_ref text NOT NULL REFERENCES defense_patch_proposals(patch_ref) ON DELETE RESTRICT,
    approved_by text NOT NULL DEFAULT 'owner',
    approval_reason text NOT NULL,
    approval_hash text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_patch_approvals_ref_format CHECK (approval_ref ~ '^KPA1-[0-9a-f]{32}$'),
    CONSTRAINT defense_patch_approvals_hash_format CHECK (approval_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_patch_approvals_nonempty CHECK (btrim(approved_by) <> '' AND btrim(approval_reason) <> '')
);
CREATE INDEX IF NOT EXISTS defense_patch_approvals_patch_idx ON defense_patch_approvals (patch_ref, created_at DESC);

CREATE TABLE IF NOT EXISTS defense_proof_of_fix (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    proof_ref text NOT NULL UNIQUE,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    finding_ref text NOT NULL REFERENCES defense_program_findings(finding_ref) ON DELETE RESTRICT,
    patch_ref text NOT NULL REFERENCES defense_patch_proposals(patch_ref) ON DELETE RESTRICT,
    before_verification_ref text REFERENCES defense_verification_runs(verification_ref) ON DELETE RESTRICT,
    after_verification_ref text NOT NULL REFERENCES defense_verification_runs(verification_ref) ON DELETE RESTRICT,
    status text NOT NULL,
    evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    proof_hash text NOT NULL,
    verdict_authority boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_proof_of_fix_ref_format CHECK (proof_ref ~ '^KPF1-[0-9a-f]{32}$'),
    CONSTRAINT defense_proof_of_fix_status_check CHECK (status IN ('verified','failed','partial','blocked')),
    CONSTRAINT defense_proof_of_fix_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
    CONSTRAINT defense_proof_of_fix_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_proof_of_fix_hash_format CHECK (proof_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_proof_of_fix_no_verdict_authority CHECK (verdict_authority = false)
);

DROP TRIGGER IF EXISTS defense_verification_runs_immutable ON defense_verification_runs;
CREATE TRIGGER defense_verification_runs_immutable BEFORE UPDATE OR DELETE ON defense_verification_runs
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
DROP TRIGGER IF EXISTS defense_patch_proposals_immutable ON defense_patch_proposals;
CREATE TRIGGER defense_patch_proposals_immutable BEFORE UPDATE OR DELETE ON defense_patch_proposals
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
DROP TRIGGER IF EXISTS defense_patch_approvals_immutable ON defense_patch_approvals;
CREATE TRIGGER defense_patch_approvals_immutable BEFORE UPDATE OR DELETE ON defense_patch_approvals
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
DROP TRIGGER IF EXISTS defense_proof_of_fix_immutable ON defense_proof_of_fix;
CREATE TRIGGER defense_proof_of_fix_immutable BEFORE UPDATE OR DELETE ON defense_proof_of_fix
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();