UPDATE tradepi_agent_followups f
SET channel_account_id=l.channel_account_id,
    updated_at=NOW()
FROM tradepi_agent_leads l
WHERE f.channel_account_id IS NULL
  AND l.channel_account_id IS NOT NULL
  AND f.tenant_id=l.tenant_id
  AND f.channel=l.channel
  AND f.external_id=l.external_id
  AND f.status IN ('pending','failed');
