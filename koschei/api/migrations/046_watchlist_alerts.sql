CREATE TABLE IF NOT EXISTS watchlist_targets (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_subject text NOT NULL,
    email text NOT NULL DEFAULT '',
    target text NOT NULL,
    target_type text NOT NULL DEFAULT 'token',
    network text NOT NULL DEFAULT 'solana-mainnet',
    label text NOT NULL DEFAULT '',
    status text NOT NULL DEFAULT 'active',
    alert_threshold integer NOT NULL DEFAULT 50 CHECK (alert_threshold >= 0 AND alert_threshold <= 100),
    last_score integer CHECK (last_score IS NULL OR (last_score >= 0 AND last_score <= 100)),
    last_risk_level text NOT NULL DEFAULT '',
    last_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
    last_checked_at timestamptz,
    next_check_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT watchlist_targets_type_check CHECK (target_type IN ('token','wallet','program','pool')),
    CONSTRAINT watchlist_targets_status_check CHECK (status IN ('active','paused')),
    UNIQUE (auth_subject, network, target)
);

CREATE INDEX IF NOT EXISTS idx_watchlist_targets_owner_updated
    ON watchlist_targets (auth_subject, updated_at DESC);
CREATE INDEX IF NOT EXISTS idx_watchlist_targets_due
    ON watchlist_targets (status, next_check_at)
    WHERE status = 'active';

CREATE TABLE IF NOT EXISTS watchlist_alerts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    watchlist_id uuid NOT NULL REFERENCES watchlist_targets(id) ON DELETE CASCADE,
    auth_subject text NOT NULL,
    event_type text NOT NULL,
    severity text NOT NULL DEFAULT 'info',
    title text NOT NULL,
    message text NOT NULL,
    previous_value jsonb NOT NULL DEFAULT '{}'::jsonb,
    current_value jsonb NOT NULL DEFAULT '{}'::jsonb,
    evidence jsonb NOT NULL DEFAULT '{}'::jsonb,
    status text NOT NULL DEFAULT 'new',
    created_at timestamptz NOT NULL DEFAULT now(),
    read_at timestamptz,
    CONSTRAINT watchlist_alerts_severity_check CHECK (severity IN ('info','low','medium','high','critical')),
    CONSTRAINT watchlist_alerts_status_check CHECK (status IN ('new','read'))
);

CREATE INDEX IF NOT EXISTS idx_watchlist_alerts_owner_status_created
    ON watchlist_alerts (auth_subject, status, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_watchlist_alerts_target_created
    ON watchlist_alerts (watchlist_id, created_at DESC);
