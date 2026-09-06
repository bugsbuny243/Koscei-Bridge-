-- Retired asset-gated product access is no longer part of Koschei Web3.
-- Existing deployments may still contain the historical snapshot table;
-- fresh deployments may never have created it. The cleanup is therefore
-- intentionally idempotent.
DROP TABLE IF EXISTS token_access_snapshots;
