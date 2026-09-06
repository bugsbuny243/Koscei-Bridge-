-- Refocus advanced modules as user-facing products while keeping admin as a status/usage surface.
UPDATE koschei_modules
SET title = 'Builder Funding Assistant',
    description = 'Template-based, copy-ready funding application generator.',
    admin_only = false,
    updated_at = now()
WHERE module_key = 'grant_autopilot';

UPDATE koschei_modules
SET admin_only = false,
    updated_at = now()
WHERE module_key IN ('agent_api', 'x402_pay_per_tool');

INSERT INTO tool_usage_prices(tool_key, display_name, price_usd, payment_mode) VALUES
('cross_chain_risk', 'Cross-chain Risk Monitor', 0, 'disabled'),
('sybil_check', 'Sybil Check', 0, 'disabled'),
('funding_assistant', 'Builder Funding Assistant', 0, 'disabled')
ON CONFLICT (tool_key) DO UPDATE SET
    display_name = EXCLUDED.display_name,
    payment_mode = EXCLUDED.payment_mode,
    updated_at = now();
