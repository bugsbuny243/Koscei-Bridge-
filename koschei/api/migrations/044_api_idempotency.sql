ALTER TABLE IF EXISTS api_usage_events
  ADD COLUMN IF NOT EXISTS idempotency_key text;

CREATE UNIQUE INDEX IF NOT EXISTS idx_api_usage_idempotency
  ON api_usage_events (api_key_id, endpoint, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_api_usage_request_lookup
  ON api_usage_events (api_key_id, request_id, created_at DESC);
