CREATE TABLE IF NOT EXISTS unified_reports (
    request_id TEXT PRIMARY KEY,
    user_id TEXT,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    overall_score INTEGER NOT NULL CHECK (overall_score >= 0 AND overall_score <= 100),
    risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW', 'MEDIUM', 'HIGH', 'CRITICAL', 'UNKNOWN')),
    module_results JSONB NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_unified_reports_user_created_at
    ON unified_reports (user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS idx_unified_reports_target
    ON unified_reports (target_type, target_id);
