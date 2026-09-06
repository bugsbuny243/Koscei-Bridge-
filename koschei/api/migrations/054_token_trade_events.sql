CREATE TABLE IF NOT EXISTS token_trade_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    mint text NOT NULL,
    trader text NOT NULL,
    side text NOT NULL,
    sol_amount numeric NOT NULL DEFAULT 0,
    token_amount numeric NOT NULL DEFAULT 0,
    slot bigint,
    block_time timestamptz,
    signature text NOT NULL,
    source text NOT NULL DEFAULT 'pumpportal',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT token_trade_events_side_check CHECK (side IN ('buy','sell','unknown')),
    CONSTRAINT token_trade_events_signature_unique UNIQUE (signature)
);

CREATE INDEX IF NOT EXISTS idx_token_trade_events_mint
    ON token_trade_events (mint);
CREATE INDEX IF NOT EXISTS idx_token_trade_events_trader
    ON token_trade_events (trader);
CREATE INDEX IF NOT EXISTS idx_token_trade_events_mint_slot
    ON token_trade_events (mint, slot);
CREATE INDEX IF NOT EXISTS idx_token_trade_events_block_time
    ON token_trade_events (block_time DESC);

ALTER TABLE IF EXISTS token_structural_signals
    ADD COLUMN IF NOT EXISTS launch_forensics_risk integer NOT NULL DEFAULT 0,
    ADD COLUMN IF NOT EXISTS launch_forensics_observed_at timestamptz;
