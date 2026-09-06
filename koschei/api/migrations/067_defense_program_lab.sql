CREATE TABLE IF NOT EXISTS defense_program_graph_nodes (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    node_ref text NOT NULL UNIQUE,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    node_type text NOT NULL,
    node_key text NOT NULL,
    label text NOT NULL,
    properties jsonb NOT NULL DEFAULT '{}'::jsonb,
    source_artifact_ref text REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    evidence_status text NOT NULL DEFAULT 'observed',
    valid_from timestamptz,
    valid_to timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_program_graph_nodes_ref_format CHECK (node_ref ~ '^KDN1-[0-9a-f]{32}$'),
    CONSTRAINT defense_program_graph_nodes_type_check CHECK (node_type IN ('program','instruction','account','pda','cpi_program','authority','artifact','finding')),
    CONSTRAINT defense_program_graph_nodes_status_check CHECK (evidence_status IN ('verified','observed','inferred','unverified')),
    CONSTRAINT defense_program_graph_nodes_properties_object CHECK (jsonb_typeof(properties) = 'object'),
    CONSTRAINT defense_program_graph_nodes_validity CHECK (valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from),
    CONSTRAINT defense_program_graph_nodes_nonempty CHECK (btrim(program_id) <> '' AND btrim(node_key) <> '' AND btrim(label) <> '')
);
CREATE INDEX IF NOT EXISTS defense_program_graph_nodes_program_idx
    ON defense_program_graph_nodes (program_id, network, node_type, created_at DESC);

CREATE TABLE IF NOT EXISTS defense_program_graph_edges (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    edge_ref text NOT NULL UNIQUE,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    from_node_ref text NOT NULL REFERENCES defense_program_graph_nodes(node_ref) ON DELETE RESTRICT,
    to_node_ref text NOT NULL REFERENCES defense_program_graph_nodes(node_ref) ON DELETE RESTRICT,
    relation text NOT NULL,
    properties jsonb NOT NULL DEFAULT '{}'::jsonb,
    source_artifact_ref text REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    evidence_status text NOT NULL DEFAULT 'observed',
    valid_from timestamptz,
    valid_to timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_program_graph_edges_ref_format CHECK (edge_ref ~ '^KDE1-[0-9a-f]{32}$'),
    CONSTRAINT defense_program_graph_edges_status_check CHECK (evidence_status IN ('verified','observed','inferred','unverified')),
    CONSTRAINT defense_program_graph_edges_properties_object CHECK (jsonb_typeof(properties) = 'object'),
    CONSTRAINT defense_program_graph_edges_validity CHECK (valid_to IS NULL OR valid_from IS NULL OR valid_to >= valid_from),
    CONSTRAINT defense_program_graph_edges_nonempty CHECK (btrim(program_id) <> '' AND btrim(relation) <> '')
);
CREATE INDEX IF NOT EXISTS defense_program_graph_edges_program_idx
    ON defense_program_graph_edges (program_id, network, relation, created_at DESC);

CREATE TABLE IF NOT EXISTS defense_program_findings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    finding_ref text NOT NULL UNIQUE,
    program_id text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    rule_id text NOT NULL,
    title text NOT NULL,
    severity text NOT NULL,
    confidence text NOT NULL,
    lifecycle_status text NOT NULL,
    source_artifact_ref text REFERENCES defense_program_artifacts(artifact_ref) ON DELETE RESTRICT,
    location jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence_refs jsonb NOT NULL DEFAULT '[]'::jsonb,
    counter_evidence jsonb NOT NULL DEFAULT '[]'::jsonb,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    details jsonb NOT NULL DEFAULT '{}'::jsonb,
    verdict_authority boolean NOT NULL DEFAULT false,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_program_findings_ref_format CHECK (finding_ref ~ '^KDF1-[0-9a-f]{32}$'),
    CONSTRAINT defense_program_findings_severity_check CHECK (severity IN ('informational','low','medium','high','critical')),
    CONSTRAINT defense_program_findings_confidence_check CHECK (confidence IN ('unverified','observed','static_supported','reachable','reproduced','verified')),
    CONSTRAINT defense_program_findings_lifecycle_check CHECK (lifecycle_status IN ('hypothesis','static_supported','evidence_pending','blocked','reproduced','impact_confirmed','patch_proposed','patch_verified','rejected')),
    CONSTRAINT defense_program_findings_no_verdict_authority CHECK (verdict_authority = false),
    CONSTRAINT defense_program_findings_location_object CHECK (jsonb_typeof(location) = 'object'),
    CONSTRAINT defense_program_findings_evidence_array CHECK (jsonb_typeof(evidence_refs) = 'array'),
    CONSTRAINT defense_program_findings_counter_array CHECK (jsonb_typeof(counter_evidence) = 'array'),
    CONSTRAINT defense_program_findings_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_program_findings_details_object CHECK (jsonb_typeof(details) = 'object'),
    CONSTRAINT defense_program_findings_nonempty CHECK (btrim(program_id) <> '' AND btrim(rule_id) <> '' AND btrim(title) <> '')
);
CREATE INDEX IF NOT EXISTS defense_program_findings_program_idx
    ON defense_program_findings (program_id, network, created_at DESC);

DROP TRIGGER IF EXISTS defense_program_graph_nodes_immutable ON defense_program_graph_nodes;
CREATE TRIGGER defense_program_graph_nodes_immutable BEFORE UPDATE OR DELETE ON defense_program_graph_nodes
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
DROP TRIGGER IF EXISTS defense_program_graph_edges_immutable ON defense_program_graph_edges;
CREATE TRIGGER defense_program_graph_edges_immutable BEFORE UPDATE OR DELETE ON defense_program_graph_edges
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
DROP TRIGGER IF EXISTS defense_program_findings_immutable ON defense_program_findings;
CREATE TRIGGER defense_program_findings_immutable BEFORE UPDATE OR DELETE ON defense_program_findings
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();