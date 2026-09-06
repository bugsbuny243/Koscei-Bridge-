CREATE TABLE IF NOT EXISTS owner_chat_threads (
  id text PRIMARY KEY,
  owner_id text NOT NULL,
  title text NOT NULL DEFAULT 'Yeni sohbet',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS owner_chat_threads_owner_updated_idx
  ON owner_chat_threads (owner_id, updated_at DESC);

CREATE TABLE IF NOT EXISTS owner_chat_messages (
  id text PRIMARY KEY,
  thread_id text NOT NULL REFERENCES owner_chat_threads(id) ON DELETE CASCADE,
  role text NOT NULL CHECK (role IN ('user', 'assistant')),
  content text NOT NULL,
  context_snapshot jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS owner_chat_messages_thread_created_idx
  ON owner_chat_messages (thread_id, created_at ASC);
