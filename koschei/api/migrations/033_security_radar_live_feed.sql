CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS security_radar_targets (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  target TEXT NOT NULL,
  target_type TEXT NOT NULL DEFAULT 'unknown',
  module_id TEXT NOT NULL,
  network TEXT NOT NULL DEFAULT 'solana-mainnet',
  status TEXT NOT NULL DEFAULT 'active',
  first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE IF EXISTS security_radar_targets ADD COLUMN IF NOT EXISTS target TEXT;
ALTER TABLE IF EXISTS security_radar_targets ADD COLUMN IF NOT EXISTS target_type TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE IF EXISTS security_radar_targets ADD COLUMN IF NOT EXISTS module_id TEXT;
ALTER TABLE IF EXISTS security_radar_targets ADD COLUMN IF NOT EXISTS network TEXT NOT NULL DEFAULT 'solana-mainnet';
ALTER TABLE IF EXISTS security_radar_targets ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active';
ALTER TABLE IF EXISTS security_radar_targets ADD COLUMN IF NOT EXISTS first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE IF EXISTS security_radar_targets ADD COLUMN IF NOT EXISTS last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE IF EXISTS security_radar_targets ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE IF EXISTS security_radar_targets ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE UNIQUE INDEX IF NOT EXISTS security_radar_targets_unique_idx ON security_radar_targets (lower(target), module_id, network);
CREATE INDEX IF NOT EXISTS security_radar_targets_status_idx ON security_radar_targets (status, updated_at DESC);

CREATE TABLE IF NOT EXISTS security_radar_seen_signatures (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  signature TEXT NOT NULL,
  module_id TEXT NOT NULL,
  source_address TEXT,
  network TEXT NOT NULL DEFAULT 'solana-mainnet',
  seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  source_target TEXT,
  slot BIGINT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE IF EXISTS security_radar_seen_signatures ADD COLUMN IF NOT EXISTS signature TEXT;
ALTER TABLE IF EXISTS security_radar_seen_signatures ADD COLUMN IF NOT EXISTS module_id TEXT;
ALTER TABLE IF EXISTS security_radar_seen_signatures ADD COLUMN IF NOT EXISTS source_address TEXT;
ALTER TABLE IF EXISTS security_radar_seen_signatures ADD COLUMN IF NOT EXISTS network TEXT NOT NULL DEFAULT 'solana-mainnet';
ALTER TABLE IF EXISTS security_radar_seen_signatures ADD COLUMN IF NOT EXISTS seen_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE IF EXISTS security_radar_seen_signatures ADD COLUMN IF NOT EXISTS source_target TEXT;
ALTER TABLE IF EXISTS security_radar_seen_signatures ADD COLUMN IF NOT EXISTS slot BIGINT;
ALTER TABLE IF EXISTS security_radar_seen_signatures ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE UNIQUE INDEX IF NOT EXISTS security_radar_seen_signatures_unique_idx ON security_radar_seen_signatures (signature, module_id, network);
CREATE UNIQUE INDEX IF NOT EXISTS security_radar_seen_signatures_legacy_unique_idx ON security_radar_seen_signatures (module_id, signature);
CREATE INDEX IF NOT EXISTS security_radar_seen_signatures_source_idx ON security_radar_seen_signatures (source_address, seen_at DESC);

CREATE TABLE IF NOT EXISTS security_radar_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  module_id TEXT NOT NULL,
  target TEXT NOT NULL,
  target_type TEXT NOT NULL DEFAULT 'unknown',
  network TEXT NOT NULL DEFAULT 'solana-mainnet',
  signature TEXT,
  source_address TEXT,
  event_type TEXT NOT NULL,
  slot BIGINT,
  block_time TIMESTAMPTZ,
  signals JSONB NOT NULL DEFAULT '{}'::jsonb,
  raw_summary JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  source TEXT,
  risk_index INTEGER,
  risk_level TEXT,
  grade TEXT,
  verdict TEXT,
  recommendation TEXT,
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  rule_version TEXT DEFAULT 'koschei-security-radar-v1',
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS module_id TEXT;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS target TEXT;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS target_type TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS network TEXT NOT NULL DEFAULT 'solana-mainnet';
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS signature TEXT;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS source_address TEXT;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS event_type TEXT NOT NULL DEFAULT 'solana_signature';
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS slot BIGINT;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS block_time TIMESTAMPTZ;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS signals JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS raw_summary JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS source TEXT;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS risk_index INTEGER;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS risk_level TEXT;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS grade TEXT;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS verdict TEXT;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS recommendation TEXT;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS evidence JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS rule_version TEXT DEFAULT 'koschei-security-radar-v1';
ALTER TABLE IF EXISTS security_radar_events ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS security_radar_events_module_created_idx ON security_radar_events (module_id, created_at DESC);
CREATE INDEX IF NOT EXISTS security_radar_events_target_created_idx ON security_radar_events (target, created_at DESC);
CREATE INDEX IF NOT EXISTS security_radar_events_signature_idx ON security_radar_events (signature);

CREATE TABLE IF NOT EXISTS security_radar_verdicts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  event_id UUID REFERENCES security_radar_events(id) ON DELETE SET NULL,
  module_id TEXT NOT NULL,
  target TEXT NOT NULL,
  target_type TEXT NOT NULL DEFAULT 'unknown',
  network TEXT NOT NULL DEFAULT 'solana-mainnet',
  grade TEXT NOT NULL,
  risk_index INTEGER NOT NULL DEFAULT 0,
  risk_level TEXT NOT NULL,
  verdict TEXT NOT NULL,
  recommendation TEXT NOT NULL,
  evidence JSONB NOT NULL DEFAULT '[]'::jsonb,
  signals JSONB NOT NULL DEFAULT '{}'::jsonb,
  rule_version TEXT NOT NULL DEFAULT 'koschei-security-radar-v1',
  signed BOOLEAN NOT NULL DEFAULT true,
  signature TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  user_id TEXT,
  source TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS event_id UUID REFERENCES security_radar_events(id) ON DELETE SET NULL;
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS module_id TEXT;
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS target TEXT;
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS target_type TEXT NOT NULL DEFAULT 'unknown';
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS network TEXT NOT NULL DEFAULT 'solana-mainnet';
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS grade TEXT;
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS risk_index INTEGER NOT NULL DEFAULT 0;
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS risk_level TEXT;
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS verdict TEXT;
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS recommendation TEXT;
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS evidence JSONB NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS signals JSONB NOT NULL DEFAULT '{}'::jsonb;
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS rule_version TEXT NOT NULL DEFAULT 'koschei-security-radar-v1';
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS signed BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS signature TEXT;
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS user_id TEXT;
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS source TEXT;
ALTER TABLE IF EXISTS security_radar_verdicts ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
CREATE INDEX IF NOT EXISTS security_radar_verdicts_module_created_idx ON security_radar_verdicts (module_id, created_at DESC);
CREATE INDEX IF NOT EXISTS security_radar_verdicts_risk_created_idx ON security_radar_verdicts (risk_level, created_at DESC);
CREATE INDEX IF NOT EXISTS security_radar_verdicts_target_created_idx ON security_radar_verdicts (target, created_at DESC);
CREATE UNIQUE INDEX IF NOT EXISTS security_radar_verdicts_signature_module_idx ON security_radar_verdicts (signature, module_id) WHERE signature IS NOT NULL;

CREATE TABLE IF NOT EXISTS security_radar_sources (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  module_id TEXT NOT NULL,
  label TEXT NOT NULL,
  address TEXT NOT NULL,
  network TEXT NOT NULL DEFAULT 'solana-mainnet',
  enabled BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  name TEXT,
  target TEXT,
  target_type TEXT DEFAULT 'program',
  provider TEXT DEFAULT 'alchemy',
  watch_mode TEXT DEFAULT 'polling',
  last_seen_signature TEXT,
  last_seen_slot BIGINT
);
ALTER TABLE IF EXISTS security_radar_sources ADD COLUMN IF NOT EXISTS module_id TEXT;
ALTER TABLE IF EXISTS security_radar_sources ADD COLUMN IF NOT EXISTS label TEXT;
ALTER TABLE IF EXISTS security_radar_sources ADD COLUMN IF NOT EXISTS address TEXT;
ALTER TABLE IF EXISTS security_radar_sources ADD COLUMN IF NOT EXISTS network TEXT NOT NULL DEFAULT 'solana-mainnet';
ALTER TABLE IF EXISTS security_radar_sources ADD COLUMN IF NOT EXISTS enabled BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE IF EXISTS security_radar_sources ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE IF EXISTS security_radar_sources ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();
ALTER TABLE IF EXISTS security_radar_sources ADD COLUMN IF NOT EXISTS name TEXT;
ALTER TABLE IF EXISTS security_radar_sources ADD COLUMN IF NOT EXISTS target TEXT;
ALTER TABLE IF EXISTS security_radar_sources ADD COLUMN IF NOT EXISTS target_type TEXT DEFAULT 'program';
ALTER TABLE IF EXISTS security_radar_sources ADD COLUMN IF NOT EXISTS provider TEXT DEFAULT 'alchemy';
ALTER TABLE IF EXISTS security_radar_sources ADD COLUMN IF NOT EXISTS watch_mode TEXT DEFAULT 'polling';
ALTER TABLE IF EXISTS security_radar_sources ADD COLUMN IF NOT EXISTS last_seen_signature TEXT;
ALTER TABLE IF EXISTS security_radar_sources ADD COLUMN IF NOT EXISTS last_seen_slot BIGINT;
CREATE UNIQUE INDEX IF NOT EXISTS security_radar_sources_unique_idx ON security_radar_sources (module_id, address, network);
CREATE UNIQUE INDEX IF NOT EXISTS security_radar_sources_legacy_unique_idx ON security_radar_sources (module_id, target) WHERE target IS NOT NULL;
CREATE INDEX IF NOT EXISTS security_radar_sources_enabled_idx ON security_radar_sources (enabled, updated_at DESC);
