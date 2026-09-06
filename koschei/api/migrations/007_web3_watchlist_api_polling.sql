CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS web3_event_sources (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT,
  email TEXT,
  name TEXT,
  label TEXT,
  provider TEXT NOT NULL DEFAULT 'alchemy',
  chain TEXT,
  network TEXT,
  address TEXT,
  source_type TEXT NOT NULL DEFAULT 'wallet',
  notes TEXT,
  status TEXT NOT NULL DEFAULT 'active',
  provider_setup_status TEXT NOT NULL DEFAULT 'api_polling',
  is_active BOOLEAN NOT NULL DEFAULT true,
  verification_mode TEXT NOT NULL DEFAULT 'api_polling',
  last_event_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE web3_event_sources
  ADD COLUMN IF NOT EXISTS user_id TEXT,
  ADD COLUMN IF NOT EXISTS email TEXT,
  ADD COLUMN IF NOT EXISTS name TEXT,
  ADD COLUMN IF NOT EXISTS label TEXT,
  ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'alchemy',
  ADD COLUMN IF NOT EXISTS chain TEXT,
  ADD COLUMN IF NOT EXISTS network TEXT,
  ADD COLUMN IF NOT EXISTS address TEXT,
  ADD COLUMN IF NOT EXISTS source_type TEXT NOT NULL DEFAULT 'wallet',
  ADD COLUMN IF NOT EXISTS notes TEXT,
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active',
  ADD COLUMN IF NOT EXISTS provider_setup_status TEXT NOT NULL DEFAULT 'api_polling',
  ADD COLUMN IF NOT EXISTS is_active BOOLEAN NOT NULL DEFAULT true,
  ADD COLUMN IF NOT EXISTS verification_mode TEXT NOT NULL DEFAULT 'api_polling',
  ADD COLUMN IF NOT EXISTS last_event_at TIMESTAMPTZ,
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  ADD COLUMN IF NOT EXISTS updated_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Compatibility-only columns retained for deployments that already created them.
ALTER TABLE web3_event_sources ADD COLUMN IF NOT EXISTS setup_token TEXT;
ALTER TABLE web3_event_sources ADD COLUMN IF NOT EXISTS webhook_url TEXT;
ALTER TABLE web3_event_sources ADD COLUMN IF NOT EXISTS secret_hash TEXT;
ALTER TABLE web3_event_sources ADD COLUMN IF NOT EXISTS disabled_reason TEXT;

UPDATE web3_event_sources
SET
  email = COALESCE(email, user_id),
  name = COALESCE(name, label),
  label = COALESCE(label, name),
  provider = COALESCE(provider, 'alchemy'),
  chain = COALESCE(chain, 'base'),
  network = COALESCE(network, 'base-mainnet'),
  source_type = COALESCE(source_type, 'wallet'),
  status = CASE WHEN COALESCE(is_active, true) THEN COALESCE(NULLIF(status, 'waiting_for_setup'), 'active') ELSE 'inactive' END,
  provider_setup_status = COALESCE(NULLIF(provider_setup_status, 'manual_required'), 'api_polling'),
  verification_mode = COALESCE(NULLIF(verification_mode, 'alchemy_signature'), 'api_polling'),
  updated_at = now();

CREATE INDEX IF NOT EXISTS web3_event_sources_email_idx ON web3_event_sources (lower(email));
CREATE INDEX IF NOT EXISTS web3_event_sources_email_status_idx ON web3_event_sources (lower(email), status);
CREATE INDEX IF NOT EXISTS web3_event_sources_address_idx ON web3_event_sources (lower(address));
CREATE INDEX IF NOT EXISTS web3_event_sources_status_idx ON web3_event_sources (status);

CREATE TABLE IF NOT EXISTS web3_events (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  source_id UUID,
  user_id TEXT,
  email TEXT,
  provider TEXT NOT NULL DEFAULT 'alchemy',
  chain TEXT,
  network TEXT,
  event_type TEXT,
  address TEXT,
  tx_hash TEXT,
  block_number TEXT,
  direction TEXT,
  asset_type TEXT,
  amount TEXT,
  raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  verification_status TEXT NOT NULL DEFAULT 'api_polling',
  status TEXT NOT NULL DEFAULT 'received',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

ALTER TABLE web3_events
  ADD COLUMN IF NOT EXISTS source_id UUID,
  ADD COLUMN IF NOT EXISTS user_id TEXT,
  ADD COLUMN IF NOT EXISTS email TEXT,
  ADD COLUMN IF NOT EXISTS provider TEXT NOT NULL DEFAULT 'alchemy',
  ADD COLUMN IF NOT EXISTS chain TEXT,
  ADD COLUMN IF NOT EXISTS network TEXT,
  ADD COLUMN IF NOT EXISTS event_type TEXT,
  ADD COLUMN IF NOT EXISTS address TEXT,
  ADD COLUMN IF NOT EXISTS tx_hash TEXT,
  ADD COLUMN IF NOT EXISTS block_number TEXT,
  ADD COLUMN IF NOT EXISTS direction TEXT,
  ADD COLUMN IF NOT EXISTS asset_type TEXT,
  ADD COLUMN IF NOT EXISTS amount TEXT,
  ADD COLUMN IF NOT EXISTS raw_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  ADD COLUMN IF NOT EXISTS verification_status TEXT NOT NULL DEFAULT 'api_polling',
  ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'received',
  ADD COLUMN IF NOT EXISTS created_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- Compatibility-only columns retained for older readers and previous event rows.
ALTER TABLE web3_events
  ADD COLUMN IF NOT EXISTS source_name TEXT,
  ADD COLUMN IF NOT EXISTS wallet_address TEXT,
  ADD COLUMN IF NOT EXISTS contract_address TEXT,
  ADD COLUMN IF NOT EXISTS token_id TEXT,
  ADD COLUMN IF NOT EXISTS amount_text TEXT,
  ADD COLUMN IF NOT EXISTS ai_summary TEXT,
  ADD COLUMN IF NOT EXISTS risk_level TEXT NOT NULL DEFAULT 'unknown',
  ADD COLUMN IF NOT EXISTS payload_hash TEXT,
  ADD COLUMN IF NOT EXISTS error_message TEXT,
  ADD COLUMN IF NOT EXISTS received_ip TEXT,
  ADD COLUMN IF NOT EXISTS received_user_agent TEXT;

UPDATE web3_events
SET
  email = COALESCE(email, user_id),
  address = COALESCE(address, wallet_address, contract_address),
  amount = COALESCE(amount, amount_text),
  provider = COALESCE(provider, 'alchemy'),
  verification_status = COALESCE(NULLIF(verification_status, 'verified'), 'api_polling'),
  status = COALESCE(status, 'received');

CREATE INDEX IF NOT EXISTS web3_events_email_created_at_idx ON web3_events (lower(email), created_at DESC);
CREATE INDEX IF NOT EXISTS web3_events_source_id_idx ON web3_events (source_id);
CREATE INDEX IF NOT EXISTS web3_events_tx_hash_idx ON web3_events (tx_hash);
CREATE UNIQUE INDEX IF NOT EXISTS web3_events_polling_dedupe_idx
  ON web3_events (source_id, lower(address), tx_hash, event_type)
  WHERE source_id IS NOT NULL AND address IS NOT NULL AND tx_hash IS NOT NULL AND event_type IS NOT NULL;
