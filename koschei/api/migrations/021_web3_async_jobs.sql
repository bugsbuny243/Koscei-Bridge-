CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS web3_jobs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  user_id TEXT,
  email TEXT,
  job_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'queued',
  network TEXT,
  target TEXT,
  request_payload JSONB NOT NULL DEFAULT '{}'::jsonb,
  result_payload JSONB,
  error_code TEXT,
  error_message TEXT,
  progress INTEGER NOT NULL DEFAULT 0,
  attempts INTEGER NOT NULL DEFAULT 0,
  max_attempts INTEGER NOT NULL DEFAULT 3,
  queued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  started_at TIMESTAMPTZ,
  completed_at TIMESTAMPTZ,
  failed_at TIMESTAMPTZ,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS web3_jobs_user_created_idx ON web3_jobs (user_id, queued_at DESC);
CREATE INDEX IF NOT EXISTS web3_jobs_status_idx ON web3_jobs (status);
CREATE INDEX IF NOT EXISTS web3_jobs_type_status_idx ON web3_jobs (job_type, status);
CREATE INDEX IF NOT EXISTS web3_jobs_target_idx ON web3_jobs (network, target);
