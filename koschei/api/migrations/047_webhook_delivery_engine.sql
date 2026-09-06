CREATE TABLE IF NOT EXISTS webhook_endpoints (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_subject text NOT NULL,
    name text NOT NULL,
    url text NOT NULL,
    secret_ciphertext text NOT NULL,
    secret_last4 text NOT NULL,
    status text NOT NULL DEFAULT 'active',
    event_types text[] NOT NULL DEFAULT ARRAY['watchlist.alert.created']::text[],
    failure_count integer NOT NULL DEFAULT 0,
    last_delivery_at timestamptz,
    last_success_at timestamptz,
    last_failure_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT webhook_endpoints_status_check CHECK (status IN ('active','paused')),
    CONSTRAINT webhook_endpoints_name_length CHECK (char_length(name) BETWEEN 1 AND 80),
    UNIQUE (auth_subject, name)
);

CREATE INDEX IF NOT EXISTS idx_webhook_endpoints_owner_updated
    ON webhook_endpoints (auth_subject, updated_at DESC);

CREATE TABLE IF NOT EXISTS webhook_deliveries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    endpoint_id uuid NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    auth_subject text NOT NULL,
    event_id uuid,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    attempt_count integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 6,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_at timestamptz,
    last_http_status integer,
    last_error text,
    response_excerpt text,
    delivered_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT webhook_deliveries_status_check CHECK (status IN ('pending','processing','retry','delivered','dead_letter')),
    CONSTRAINT webhook_deliveries_attempt_check CHECK (attempt_count >= 0 AND max_attempts BETWEEN 1 AND 12),
    UNIQUE (endpoint_id, event_id, event_type)
);

CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_due
    ON webhook_deliveries (status, next_attempt_at, created_at)
    WHERE status IN ('pending','retry');
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_owner_created
    ON webhook_deliveries (auth_subject, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_webhook_deliveries_endpoint_created
    ON webhook_deliveries (endpoint_id, created_at DESC);

CREATE OR REPLACE FUNCTION enqueue_watchlist_alert_webhooks()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    INSERT INTO webhook_deliveries (endpoint_id, auth_subject, event_id, event_type, payload)
    SELECT
        e.id,
        NEW.auth_subject,
        NEW.id,
        'watchlist.alert.created',
        jsonb_build_object(
            'id', NEW.id::text,
            'type', 'watchlist.alert.created',
            'created_at', NEW.created_at,
            'data', jsonb_build_object(
                'watchlist_id', NEW.watchlist_id::text,
                'target', t.target,
                'target_type', t.target_type,
                'network', t.network,
                'label', t.label,
                'event_type', NEW.event_type,
                'severity', NEW.severity,
                'title', NEW.title,
                'message', NEW.message,
                'previous_value', NEW.previous_value,
                'current_value', NEW.current_value,
                'evidence', NEW.evidence
            )
        )
    FROM webhook_endpoints e
    JOIN watchlist_targets t ON t.id = NEW.watchlist_id
    WHERE e.auth_subject = NEW.auth_subject
      AND e.status = 'active'
      AND 'watchlist.alert.created' = ANY(e.event_types)
    ON CONFLICT (endpoint_id, event_id, event_type) DO NOTHING;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_watchlist_alert_webhook_enqueue ON watchlist_alerts;
CREATE TRIGGER trg_watchlist_alert_webhook_enqueue
AFTER INSERT ON watchlist_alerts
FOR EACH ROW
EXECUTE FUNCTION enqueue_watchlist_alert_webhooks();
