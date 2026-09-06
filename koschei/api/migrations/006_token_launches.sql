CREATE TABLE IF NOT EXISTS token_launches (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  mint_address TEXT NOT NULL UNIQUE,
  network TEXT NOT NULL DEFAULT 'solana-mainnet',
  risk_score INTEGER DEFAULT 0,
  risk_level TEXT DEFAULT 'UNKNOWN',
  risk_summary TEXT DEFAULT '',
  is_renounced BOOLEAN DEFAULT FALSE,
  is_frozen BOOLEAN DEFAULT FALSE,
  tx_count INTEGER DEFAULT 0,
  findings JSONB DEFAULT '[]',
  submitted_by TEXT DEFAULT 'anonymous',
  created_at TIMESTAMPTZ DEFAULT now()
);
CREATE INDEX IF NOT EXISTS token_launches_created_idx
ON token_launches (created_at DESC);
CREATE INDEX IF NOT EXISTS token_launches_score_idx
ON token_launches (risk_score ASC);
