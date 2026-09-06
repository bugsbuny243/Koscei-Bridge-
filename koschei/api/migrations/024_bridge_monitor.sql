CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS exploit_simulation_runs (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    program_id text NOT NULL,
    chain text NOT NULL DEFAULT 'solana',
    status text NOT NULL DEFAULT 'queued',
    fuzz_execs_per_second integer NOT NULL DEFAULT 0,
    critical_findings integer NOT NULL DEFAULT 0,
    estimated_exploit_loss_prevented_usd numeric(20, 2) NOT NULL DEFAULT 0,
    report_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    completed_at timestamptz NULL
);
CREATE INDEX IF NOT EXISTS idx_exploit_runs_program_created ON exploit_simulation_runs (program_id, created_at DESC);

CREATE TABLE IF NOT EXISTS exploit_findings (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    run_id uuid REFERENCES exploit_simulation_runs(id) ON DELETE CASCADE,
    severity text NOT NULL DEFAULT 'info',
    category text NOT NULL DEFAULT '',
    title text NOT NULL,
    repro_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_exploit_findings_run_severity ON exploit_findings (run_id, severity);

CREATE TABLE IF NOT EXISTS bridge_risk_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    bridge_name text NOT NULL,
    source_chain text NOT NULL DEFAULT '',
    destination_chain text NOT NULL DEFAULT '',
    bridge_outflow_anomaly_usd numeric(20, 2) NOT NULL DEFAULT 0,
    risk_score integer NOT NULL DEFAULT 0,
    event_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    observed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_bridge_risk_events_bridge_observed ON bridge_risk_events (bridge_name, observed_at DESC);

CREATE TABLE IF NOT EXISTS por_monitor_snapshots (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    exchange text NOT NULL,
    asset_symbol text NOT NULL DEFAULT '',
    merkle_root text NOT NULL DEFAULT '',
    assets_usd numeric(20, 2) NOT NULL DEFAULT 0,
    liabilities_usd numeric(20, 2) NOT NULL DEFAULT 0,
    reserve_ratio numeric(12, 6) NOT NULL DEFAULT 0,
    reserve_ratio_delta numeric(12, 6) NOT NULL DEFAULT 0,
    verified_merkle_batches_count integer NOT NULL DEFAULT 0,
    snapshot_payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    observed_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_por_snapshots_exchange_observed ON por_monitor_snapshots (exchange, observed_at DESC);
