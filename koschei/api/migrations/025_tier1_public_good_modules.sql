CREATE EXTENSION IF NOT EXISTS pgcrypto;

ALTER TABLE mev_protection_events ADD COLUMN IF NOT EXISTS mev_saved_usd numeric(20, 2) NOT NULL DEFAULT 0;
ALTER TABLE mev_protection_events ADD COLUMN IF NOT EXISTS raw_payload jsonb NOT NULL DEFAULT '{}'::jsonb;
UPDATE mev_protection_events SET mev_saved_usd = estimated_loss_usd WHERE mev_saved_usd = 0 AND estimated_loss_usd > 0;

CREATE TABLE IF NOT EXISTS impact_tweet_drafts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    draft_date date NOT NULL UNIQUE,
    draft_text text NOT NULL,
    metrics_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_impact_tweet_drafts_date ON impact_tweet_drafts (draft_date DESC);

CREATE INDEX IF NOT EXISTS idx_mev_protection_saved_created ON mev_protection_events (mev_saved_usd DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_liquidity_alerts_loss_created ON liquidity_drain_alerts (loss_prevented_usd DESC, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_proposal_risks_protected_created ON proposal_risks (estimated_outflow_usd DESC, created_at DESC) WHERE risk_score >= 70;
