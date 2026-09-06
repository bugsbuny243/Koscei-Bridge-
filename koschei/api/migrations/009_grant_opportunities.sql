CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS grant_opportunities (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  title TEXT NOT NULL,
  ecosystem TEXT NOT NULL DEFAULT '',
  source_url TEXT NOT NULL DEFAULT '',
  category TEXT NOT NULL DEFAULT '',
  reward_range TEXT NOT NULL DEFAULT '',
  deadline TEXT NOT NULL DEFAULT '',
  status TEXT NOT NULL DEFAULT 'watching',
  fit_score INTEGER NOT NULL DEFAULT 0 CHECK (fit_score >= 0 AND fit_score <= 100),
  notes TEXT NOT NULL DEFAULT '',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  CONSTRAINT grant_opportunities_status_check CHECK (status IN ('watching', 'apply_now', 'applied', 'won', 'rejected', 'archived'))
);

CREATE INDEX IF NOT EXISTS grant_opportunities_status_fit_idx
  ON grant_opportunities (status, fit_score DESC, updated_at DESC);
