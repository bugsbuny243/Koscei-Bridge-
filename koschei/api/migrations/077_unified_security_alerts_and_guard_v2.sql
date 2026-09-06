CREATE OR REPLACE FUNCTION security_alert_severity_rank(value text)
RETURNS integer
LANGUAGE sql
IMMUTABLE
AS $$
    SELECT CASE lower(COALESCE(value,''))
        WHEN 'critical' THEN 5
        WHEN 'high' THEN 4
        WHEN 'medium' THEN 3
        WHEN 'low' THEN 2
        ELSE 1
    END;
$$;

CREATE TABLE IF NOT EXISTS security_alert_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    auth_subject text,
    source text NOT NULL,
    event_type text NOT NULL,
    severity text NOT NULL,
    target text NOT NULL DEFAULT '',
    title text NOT NULL,
    message text NOT NULL,
    dedupe_key text NOT NULL UNIQUE,
    occurrence_count integer NOT NULL DEFAULT 1,
    payload jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT security_alert_events_severity_check CHECK (severity IN ('info','low','medium','high','critical')),
    CONSTRAINT security_alert_events_nonempty_check CHECK (btrim(source) <> '' AND btrim(event_type) <> '' AND btrim(title) <> '' AND btrim(dedupe_key) <> ''),
    CONSTRAINT security_alert_events_occurrence_check CHECK (occurrence_count > 0)
);

CREATE INDEX IF NOT EXISTS security_alert_events_created_idx
    ON security_alert_events (created_at DESC);
CREATE INDEX IF NOT EXISTS security_alert_events_target_idx
    ON security_alert_events (target, created_at DESC);
CREATE INDEX IF NOT EXISTS security_alert_events_owner_idx
    ON security_alert_events (auth_subject, created_at DESC)
    WHERE auth_subject IS NOT NULL;
CREATE INDEX IF NOT EXISTS security_alert_events_severity_idx
    ON security_alert_events (severity, created_at DESC);

CREATE TABLE IF NOT EXISTS security_alert_deliveries (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    alert_id uuid NOT NULL REFERENCES security_alert_events(id) ON DELETE CASCADE,
    channel text NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    attempt_count integer NOT NULL DEFAULT 0,
    max_attempts integer NOT NULL DEFAULT 6,
    next_attempt_at timestamptz NOT NULL DEFAULT now(),
    locked_at timestamptz,
    last_http_status integer,
    last_error text,
    delivered_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT security_alert_deliveries_channel_check CHECK (channel IN ('telegram','discord')),
    CONSTRAINT security_alert_deliveries_status_check CHECK (status IN ('pending','processing','retry','delivered','dead_letter')),
    CONSTRAINT security_alert_deliveries_attempt_check CHECK (attempt_count >= 0 AND max_attempts BETWEEN 1 AND 12),
    UNIQUE (alert_id, channel)
);

CREATE INDEX IF NOT EXISTS security_alert_deliveries_due_idx
    ON security_alert_deliveries (status, next_attempt_at, created_at)
    WHERE status IN ('pending','retry');

CREATE TABLE IF NOT EXISTS security_alert_webhook_subscriptions (
    endpoint_id uuid NOT NULL REFERENCES webhook_endpoints(id) ON DELETE CASCADE,
    auth_subject text NOT NULL,
    event_type text NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (endpoint_id,event_type),
    CONSTRAINT security_alert_webhook_event_type_check CHECK (
        event_type IN ('security.alert.created','arvis.verdict.created','transaction.guard.decision')
    )
);

CREATE INDEX IF NOT EXISTS security_alert_webhook_subscriptions_owner_idx
    ON security_alert_webhook_subscriptions (auth_subject,created_at DESC);

CREATE OR REPLACE FUNCTION enqueue_security_alert_webhooks()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF COALESCE(btrim(NEW.auth_subject), '') = '' THEN
        RETURN NEW;
    END IF;

    INSERT INTO webhook_deliveries (endpoint_id, auth_subject, event_id, event_type, payload)
    SELECT
        e.id,
        NEW.auth_subject,
        NEW.id,
        NEW.event_type,
        jsonb_build_object(
            'id', NEW.id::text,
            'type', NEW.event_type,
            'created_at', NEW.created_at,
            'data', jsonb_build_object(
                'source', NEW.source,
                'severity', NEW.severity,
                'target', NEW.target,
                'title', NEW.title,
                'message', NEW.message,
                'occurrence_count', NEW.occurrence_count,
                'payload', NEW.payload
            )
        )
    FROM webhook_endpoints e
    JOIN security_alert_webhook_subscriptions s
      ON s.endpoint_id=e.id AND s.auth_subject=e.auth_subject
    WHERE e.auth_subject = NEW.auth_subject
      AND e.status = 'active'
      AND (s.event_type='security.alert.created' OR s.event_type=NEW.event_type)
    GROUP BY e.id,e.auth_subject
    ON CONFLICT (endpoint_id, event_id, event_type) DO NOTHING;

    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS trg_security_alert_webhook_enqueue ON security_alert_events;
CREATE TRIGGER trg_security_alert_webhook_enqueue
AFTER INSERT ON security_alert_events
FOR EACH ROW
EXECUTE FUNCTION enqueue_security_alert_webhooks();

ALTER TABLE transaction_firewall_reports
    ADD COLUMN IF NOT EXISTS guard_version text NOT NULL DEFAULT 'v1',
    ADD COLUMN IF NOT EXISTS guard_complete boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS account_deltas jsonb NOT NULL DEFAULT '[]'::jsonb,
    ADD COLUMN IF NOT EXISTS program_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS intent_policy jsonb NOT NULL DEFAULT '{}'::jsonb,
    ADD COLUMN IF NOT EXISTS alert_event_id uuid REFERENCES security_alert_events(id) ON DELETE SET NULL;

CREATE INDEX IF NOT EXISTS transaction_firewall_reports_alert_idx
    ON transaction_firewall_reports (alert_event_id)
    WHERE alert_event_id IS NOT NULL;
