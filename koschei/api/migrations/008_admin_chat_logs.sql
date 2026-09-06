CREATE TABLE IF NOT EXISTS admin_chat_logs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  message TEXT NOT NULL,
  answer TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS admin_chat_logs_created_at_idx ON admin_chat_logs (created_at DESC);
