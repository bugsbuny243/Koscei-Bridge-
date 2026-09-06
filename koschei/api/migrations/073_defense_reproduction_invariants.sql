CREATE TABLE IF NOT EXISTS defense_reproduction_invariants (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    invariant_ref text NOT NULL UNIQUE,
    invariant_version text NOT NULL,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    finding_ref text NOT NULL REFERENCES defense_program_findings(finding_ref) ON DELETE RESTRICT,
    source_artifact_ref text NOT NULL REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    command text NOT NULL,
    baseline_marker text NOT NULL,
    patched_marker text NOT NULL,
    rationale text NOT NULL,
    approved_by text NOT NULL DEFAULT 'owner',
    approval_hash text NOT NULL,
    active boolean NOT NULL DEFAULT true,
    verdict_authority boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_reproduction_invariants_ref_format CHECK (invariant_ref ~ '^KRI1-[0-9a-f]{32}$'),
    CONSTRAINT defense_reproduction_invariants_version_format CHECK (invariant_version ~ '^v[0-9]+\.[0-9]+\.[0-9]+$'),
    CONSTRAINT defense_reproduction_invariants_marker_format CHECK (
        baseline_marker ~ '^KOSCHEI_[A-Z0-9_:-]{8,120}$' AND
        patched_marker ~ '^KOSCHEI_[A-Z0-9_:-]{8,120}$' AND
        baseline_marker <> patched_marker
    ),
    CONSTRAINT defense_reproduction_invariants_approval_hash_format CHECK (approval_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_reproduction_invariants_nonempty CHECK (
        btrim(program_id) <> '' AND btrim(network) <> '' AND btrim(command) <> '' AND
        btrim(rationale) <> '' AND btrim(approved_by) <> ''
    ),
    CONSTRAINT defense_reproduction_invariants_non_authoritative CHECK (verdict_authority = false)
);

CREATE INDEX IF NOT EXISTS defense_reproduction_invariants_finding_idx
    ON defense_reproduction_invariants (finding_ref, active, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_reproduction_invariants_program_idx
    ON defense_reproduction_invariants (program_id, network, created_at DESC);

CREATE TABLE IF NOT EXISTS defense_reproduction_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_ref text NOT NULL UNIQUE,
    invariant_ref text NOT NULL REFERENCES defense_reproduction_invariants(invariant_ref) ON DELETE RESTRICT,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    finding_ref text NOT NULL REFERENCES defense_program_findings(finding_ref) ON DELETE RESTRICT,
    patch_ref text NOT NULL REFERENCES defense_patch_proposals(patch_ref) ON DELETE RESTRICT,
    baseline_job_ref text NOT NULL REFERENCES defense_worker_jobs(job_ref) ON DELETE RESTRICT,
    patched_job_ref text NOT NULL REFERENCES defense_worker_jobs(job_ref) ON DELETE RESTRICT,
    baseline_verification_ref text NOT NULL REFERENCES defense_verification_runs(verification_ref) ON DELETE RESTRICT,
    patched_verification_ref text NOT NULL REFERENCES defense_verification_runs(verification_ref) ON DELETE RESTRICT,
    baseline_marker_observed boolean NOT NULL DEFAULT false,
    patched_marker_observed boolean NOT NULL DEFAULT false,
    status text NOT NULL,
    evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    run_hash text NOT NULL,
    proof_ref text REFERENCES defense_proof_of_fix(proof_ref) ON DELETE RESTRICT,
    verdict_authority boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_reproduction_runs_ref_format CHECK (run_ref ~ '^KRR1-[0-9a-f]{32}$'),
    CONSTRAINT defense_reproduction_runs_status_check CHECK (status IN ('verified','failed','partial','blocked')),
    CONSTRAINT defense_reproduction_runs_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
    CONSTRAINT defense_reproduction_runs_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_reproduction_runs_hash_format CHECK (run_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_reproduction_runs_distinct_jobs CHECK (baseline_job_ref <> patched_job_ref),
    CONSTRAINT defense_reproduction_runs_non_authoritative CHECK (verdict_authority = false)
);

CREATE INDEX IF NOT EXISTS defense_reproduction_runs_invariant_idx
    ON defense_reproduction_runs (invariant_ref, created_at DESC);
CREATE INDEX IF NOT EXISTS defense_reproduction_runs_finding_idx
    ON defense_reproduction_runs (finding_ref, created_at DESC);

DROP TRIGGER IF EXISTS defense_reproduction_invariants_immutable ON defense_reproduction_invariants;
CREATE TRIGGER defense_reproduction_invariants_immutable
BEFORE UPDATE OR DELETE ON defense_reproduction_invariants
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();

DROP TRIGGER IF EXISTS defense_reproduction_runs_immutable ON defense_reproduction_runs;
CREATE TRIGGER defense_reproduction_runs_immutable
BEFORE UPDATE OR DELETE ON defense_reproduction_runs
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
