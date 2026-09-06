CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE IF NOT EXISTS koschei_modules (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), module_key TEXT UNIQUE NOT NULL, title TEXT NOT NULL, description TEXT, category TEXT, status TEXT DEFAULT 'active', is_public BOOLEAN DEFAULT false, admin_only BOOLEAN DEFAULT false, created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS grant_applications (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), opportunity_id UUID, ecosystem TEXT, title TEXT, status TEXT DEFAULT 'draft', project_summary TEXT, problem TEXT, solution TEXT, impact TEXT, milestones JSONB DEFAULT '[]'::jsonb, budget JSONB DEFAULT '{}'::jsonb, generated_text TEXT, created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS intelligence_graph_nodes (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT, node_type TEXT, chain TEXT, network TEXT, address TEXT, label TEXT, risk_score INT DEFAULT 0, metadata JSONB DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS intelligence_graph_edges (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT, source_node_id UUID, target_node_id UUID, relationship_type TEXT, chain TEXT, network TEXT, tx_hash TEXT, weight NUMERIC DEFAULT 1, metadata JSONB DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS risk_assessments (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT, target TEXT, chain TEXT, network TEXT, target_type TEXT, risk_score INT, severity TEXT, red_flags JSONB DEFAULT '[]'::jsonb, evidence JSONB DEFAULT '[]'::jsonb, recommendations JSONB DEFAULT '[]'::jsonb, raw_context JSONB DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS tx_decodes (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT, chain TEXT, network TEXT, tx_hash TEXT, summary TEXT, risk_score INT, decoded JSONB DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS agent_api_keys (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), owner_email TEXT, key_hash TEXT NOT NULL, label TEXT, status TEXT DEFAULT 'active', scopes JSONB DEFAULT '[]'::jsonb, created_at TIMESTAMPTZ DEFAULT now(), last_used_at TIMESTAMPTZ);
CREATE TABLE IF NOT EXISTS agent_api_logs (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), key_id UUID, endpoint TEXT, status TEXT, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS tool_usage_prices (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tool_key TEXT UNIQUE, display_name TEXT, price_usd NUMERIC, payment_mode TEXT DEFAULT 'disabled', created_at TIMESTAMPTZ DEFAULT now(), updated_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS tool_usage_logs (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT, tool_key TEXT, status TEXT, payment_reference TEXT, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS cross_chain_observations (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT, source_chain TEXT, target_chain TEXT, address TEXT, tx_hash TEXT, bridge_or_protocol TEXT, risk_score INT DEFAULT 0, observation_type TEXT, summary TEXT, raw_payload JSONB DEFAULT '{}'::jsonb, created_at TIMESTAMPTZ DEFAULT now());
CREATE TABLE IF NOT EXISTS sybil_checks (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), email TEXT, subject TEXT, check_type TEXT, score INT, signals JSONB DEFAULT '[]'::jsonb, recommendation TEXT, created_at TIMESTAMPTZ DEFAULT now());

CREATE INDEX IF NOT EXISTS graph_nodes_email_idx ON intelligence_graph_nodes (lower(email));
CREATE INDEX IF NOT EXISTS graph_edges_email_idx ON intelligence_graph_edges (lower(email));
CREATE INDEX IF NOT EXISTS risk_assessments_email_idx ON risk_assessments (lower(email), created_at DESC);
CREATE INDEX IF NOT EXISTS tx_decodes_email_idx ON tx_decodes (lower(email), created_at DESC);
CREATE INDEX IF NOT EXISTS agent_api_keys_hash_idx ON agent_api_keys (key_hash);
CREATE INDEX IF NOT EXISTS cross_chain_observations_email_idx ON cross_chain_observations (lower(email), created_at DESC);
CREATE INDEX IF NOT EXISTS sybil_checks_email_idx ON sybil_checks (lower(email), created_at DESC);

INSERT INTO koschei_modules (module_key,title,description,category,is_public,admin_only) VALUES
('grant_autopilot','Builder Funding Assistant','Template-based, copy-ready funding application generator.','Funding',false,false),
('public_impact','Public Proof of Impact','Safe public evidence and roadmap page.','Public Goods',true,false),
('intelligence_graph','Intelligence Graph','Watchlist and event relationship intelligence.','Intelligence',false,false),
('risk_engine_v2','AI Risk Engine v2','Preliminary structured risk intelligence.','Risk',false,false),
('tx_decoder_pro','TX Decoder Pro','Cross-chain human-readable transaction decoding.','Developer Tools',false,false),
('agent_api','Koschei Agent API','Read-only API for agents and external tools.','Developer Tools',false,false),
('x402_pay_per_tool','x402 Pay-per-Tool','Disabled-by-default pay-per-tool foundation.','Monetization',false,false),
('public_sdk','Public SDK + API Docs','Copyable API and SDK integration documentation.','Developer Tools',true,false),
('cross_chain_risk','Cross-chain Risk Monitor','Preliminary bridge and route risk checklist.','Risk',false,false),
('sybil_layer','Human / Sybil Resistance','Optional privacy-preserving anti-abuse checklist.','Trust',false,false)
ON CONFLICT (module_key) DO UPDATE SET title=EXCLUDED.title, description=EXCLUDED.description, category=EXCLUDED.category, is_public=EXCLUDED.is_public, admin_only=EXCLUDED.admin_only, updated_at=now();

INSERT INTO tool_usage_prices(tool_key,display_name,price_usd,payment_mode) VALUES
('wallet_score','Wallet Score',0,'disabled'),('risk_v2','Risk Engine v2',0,'disabled'),('metadata','Metadata',0,'disabled'),('tx_decode_pro','TX Decoder Pro',0,'disabled'),('intelligence_graph','Intelligence Graph',0,'disabled'),('cross_chain_risk','Cross-chain Risk Monitor',0,'disabled'),('sybil_check','Sybil Check',0,'disabled'),('funding_assistant','Builder Funding Assistant',0,'disabled')
ON CONFLICT (tool_key) DO NOTHING;
