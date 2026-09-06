-- Register Project Radar as a customer-facing, paid-credit module.
INSERT INTO koschei_modules (module_key,title,description,category,is_public,admin_only,status) VALUES
('project_radar','Project Radar','Customer-facing early Solana/Web3 project discovery with public-data signals, risk hints, and opportunity scoring.','Intelligence',false,false,'active')
ON CONFLICT (module_key) DO UPDATE SET
    title = EXCLUDED.title,
    description = EXCLUDED.description,
    category = EXCLUDED.category,
    is_public = EXCLUDED.is_public,
    admin_only = EXCLUDED.admin_only,
    status = EXCLUDED.status,
    updated_at = now();

INSERT INTO tool_usage_prices(tool_key,display_name,price_usd,payment_mode) VALUES
('project_radar','Project Radar',0,'credits')
ON CONFLICT (tool_key) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    payment_mode = EXCLUDED.payment_mode,
    updated_at = now();
