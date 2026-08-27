CREATE TABLE IF NOT EXISTS tradepi_agent_leads (
  tenant_id TEXT NOT NULL,
  channel TEXT NOT NULL,
  external_id TEXT NOT NULL,
  display_name TEXT NOT NULL DEFAULT '',
  stage TEXT NOT NULL DEFAULT 'new',
  score INTEGER NOT NULL DEFAULT 0 CHECK (score >= 0 AND score <= 100),
  budget_known BOOLEAN NOT NULL DEFAULT FALSE,
  model_known BOOLEAN NOT NULL DEFAULT FALSE,
  location_known BOOLEAN NOT NULL DEFAULT FALSE,
  trade_in_known BOOLEAN NOT NULL DEFAULT FALSE,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  PRIMARY KEY (tenant_id, channel, external_id)
);

CREATE TABLE IF NOT EXISTS tradepi_agent_messages (
  id BIGSERIAL PRIMARY KEY,
  tenant_id TEXT NOT NULL,
  channel TEXT NOT NULL,
  channel_chat_id TEXT NOT NULL DEFAULT '',
  channel_user_id TEXT NOT NULL,
  direction TEXT NOT NULL CHECK (direction IN ('inbound', 'outbound')),
  body TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS tradepi_agent_messages_conversation_idx
  ON tradepi_agent_messages (tenant_id, channel, channel_user_id, created_at DESC);

CREATE INDEX IF NOT EXISTS tradepi_agent_leads_stage_idx
  ON tradepi_agent_leads (tenant_id, stage, score DESC, updated_at DESC);
