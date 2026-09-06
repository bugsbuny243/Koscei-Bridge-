-- Durable ingress journal for PumpPortal discovery events. The live websocket
-- must not depend on a bounded in-memory channel for token/migration coverage.
CREATE TABLE IF NOT EXISTS public.pumpportal_event_inbox (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    event_key text NOT NULL UNIQUE,
    network text NOT NULL DEFAULT 'solana-mainnet',
    signature text NOT NULL DEFAULT '',
    mint text NOT NULL,
    event_type text NOT NULL,
    payload jsonb NOT NULL,
    status text NOT NULL DEFAULT 'pending',
    attempts integer NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    last_error text NOT NULL DEFAULT '',
    received_at timestamptz NOT NULL,
    processed_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT pumpportal_event_inbox_status_check CHECK (
        status IN ('pending','processing','retryable','completed','exhausted')
    )
);

CREATE INDEX IF NOT EXISTS pumpportal_event_inbox_work_idx
    ON public.pumpportal_event_inbox (status, updated_at, created_at)
    WHERE status IN ('pending','retryable','processing');

CREATE INDEX IF NOT EXISTS pumpportal_event_inbox_mint_idx
    ON public.pumpportal_event_inbox (mint, received_at DESC);

CREATE INDEX IF NOT EXISTS pumpportal_event_inbox_signature_idx
    ON public.pumpportal_event_inbox (signature)
    WHERE signature<>'';

COMMENT ON TABLE public.pumpportal_event_inbox IS
    'Durable PumpPortal discovery ingress. Events are persisted before asynchronous Security Radar projection.';
