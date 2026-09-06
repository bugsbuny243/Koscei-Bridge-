CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS plans (
  id text PRIMARY KEY,
  name text NOT NULL,
  price_try integer NOT NULL DEFAULT 0,
  monthly_credits integer NOT NULL DEFAULT 0,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS generation_jobs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,
  tool text NOT NULL,
  prompt text NOT NULL,
  route text NOT NULL DEFAULT '',
  provider text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'queued',
  result text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_generation_jobs_email_created ON generation_jobs (lower(email), created_at DESC);

CREATE TABLE IF NOT EXISTS model_route_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text,
  tool text NOT NULL DEFAULT '',
  route text NOT NULL DEFAULT '',
  model text NOT NULL DEFAULT '',
  provider text NOT NULL DEFAULT '',
  prompt text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_model_route_logs_email_created ON model_route_logs (lower(email), created_at DESC);

CREATE TABLE IF NOT EXISTS runtime_projects (
  id text PRIMARY KEY,
  email text NOT NULL,
  title text NOT NULL DEFAULT '',
  prompt text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'queued',
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_runtime_projects_email_created ON runtime_projects (lower(email), created_at DESC);

CREATE TABLE IF NOT EXISTS runtime_tasks (
  id text PRIMARY KEY,
  project_id text NOT NULL,
  email text NOT NULL DEFAULT '',
  task_type text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'queued',
  input_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  output_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  error text,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_runtime_tasks_email_created ON runtime_tasks (lower(email), created_at DESC);
CREATE INDEX IF NOT EXISTS idx_runtime_tasks_project_type ON runtime_tasks (project_id, task_type);

CREATE TABLE IF NOT EXISTS runtime_logs (
  id text PRIMARY KEY,
  project_id text NOT NULL,
  task_id text,
  level text NOT NULL DEFAULT 'info',
  message text NOT NULL DEFAULT '',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_runtime_logs_project_created ON runtime_logs (project_id, created_at DESC);

CREATE TABLE IF NOT EXISTS generated_artifacts (
  id text PRIMARY KEY,
  runtime_project_id text NOT NULL,
  user_email text NOT NULL,
  status text NOT NULL DEFAULT 'processing',
  artifact_type text NOT NULL DEFAULT 'web_app',
  title text NOT NULL DEFAULT '',
  summary text NOT NULL DEFAULT '',
  file_count integer NOT NULL DEFAULT 0,
  zip_ready boolean NOT NULL DEFAULT false,
  error_message text,
  build_status text NOT NULL DEFAULT '',
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_generated_artifacts_project_created ON generated_artifacts (runtime_project_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_generated_artifacts_user_created ON generated_artifacts (lower(user_email), created_at DESC);

CREATE TABLE IF NOT EXISTS generated_files (
  id text PRIMARY KEY,
  artifact_id text NOT NULL,
  runtime_project_id text NOT NULL,
  path text NOT NULL,
  language text NOT NULL DEFAULT '',
  purpose text NOT NULL DEFAULT '',
  action text NOT NULL DEFAULT '',
  content text NOT NULL DEFAULT '',
  content_hash text NOT NULL DEFAULT '',
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_generated_files_artifact_path ON generated_files (artifact_id, path);

CREATE TABLE IF NOT EXISTS runtime_build_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  artifact_id text NOT NULL,
  runtime_log_id text,
  level text NOT NULL DEFAULT 'info',
  message text NOT NULL DEFAULT '',
  payload jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_runtime_build_logs_artifact_created ON runtime_build_logs (artifact_id, created_at DESC);

CREATE TABLE IF NOT EXISTS web3_outputs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  email text NOT NULL,
  output_type text NOT NULL DEFAULT '',
  title text NOT NULL DEFAULT '',
  ecosystem text NOT NULL DEFAULT '',
  content_json jsonb NOT NULL DEFAULT '{}'::jsonb,
  content_text text NOT NULL DEFAULT '',
  used_ai boolean NOT NULL DEFAULT false,
  used_fallback boolean NOT NULL DEFAULT false,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_web3_outputs_email_created ON web3_outputs (lower(email), created_at DESC);

CREATE TABLE IF NOT EXISTS owner_client_orders (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  client_email text NOT NULL DEFAULT '',
  status text NOT NULL DEFAULT 'new',
  total_amount numeric(20,2) NOT NULL DEFAULT 0,
  metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
  created_at timestamptz NOT NULL DEFAULT now(),
  updated_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS owner_order_requirements (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), order_id uuid, content text NOT NULL DEFAULT '', metadata jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS owner_order_assets (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), order_id uuid, asset_url text NOT NULL DEFAULT '', metadata jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS owner_delivery_packages (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), order_id uuid, status text NOT NULL DEFAULT 'draft', metadata jsonb NOT NULL DEFAULT '{}'::jsonb, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS owner_revision_requests (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), order_id uuid, status text NOT NULL DEFAULT 'open', request text NOT NULL DEFAULT '', created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS owner_profit_records (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), order_id uuid, amount numeric(20,2) NOT NULL DEFAULT 0, currency text NOT NULL DEFAULT 'TRY', created_at timestamptz NOT NULL DEFAULT now());
CREATE TABLE IF NOT EXISTS owner_service_templates (id uuid PRIMARY KEY DEFAULT gen_random_uuid(), service_key text UNIQUE NOT NULL, title text NOT NULL, description text NOT NULL DEFAULT '', price_try integer NOT NULL DEFAULT 0, is_active boolean NOT NULL DEFAULT true, created_at timestamptz NOT NULL DEFAULT now(), updated_at timestamptz NOT NULL DEFAULT now());
CREATE INDEX IF NOT EXISTS idx_owner_client_orders_status_created ON owner_client_orders (status, created_at DESC);

CREATE TABLE IF NOT EXISTS chain_health_logs (
  id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
  chain text NOT NULL,
  network text NOT NULL DEFAULT '',
  provider text NOT NULL DEFAULT '',
  ok boolean NOT NULL DEFAULT false,
  result text NOT NULL DEFAULT '',
  error text NOT NULL DEFAULT '',
  checked_at timestamptz NOT NULL DEFAULT now(),
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_chain_health_logs_chain_checked ON chain_health_logs (lower(chain), checked_at DESC);

ALTER TABLE app_user_profiles ADD COLUMN IF NOT EXISTS status text NOT NULL DEFAULT 'active';
ALTER TABLE app_user_profiles ADD COLUMN IF NOT EXISTS wallet_address text;
ALTER TABLE app_user_profiles ADD COLUMN IF NOT EXISTS banned_at timestamptz;
ALTER TABLE app_user_profiles ADD COLUMN IF NOT EXISTS ban_reason text;

ALTER TABLE entitlements ALTER COLUMN outputs_total SET DEFAULT 0;
ALTER TABLE entitlements ALTER COLUMN outputs_remaining SET DEFAULT 0;
UPDATE entitlements
SET outputs_total = 0,
    outputs_remaining = 0,
    updated_at = now()
WHERE status = 'active'
  AND COALESCE(plan_id, 'free') = 'free'
  AND (COALESCE(outputs_total, 0) <> 0 OR COALESCE(outputs_remaining, 0) <> 0);
