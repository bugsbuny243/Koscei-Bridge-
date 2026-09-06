CREATE TABLE IF NOT EXISTS security_radar_holder_snapshots (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    scan_id text NOT NULL,
    source_verdict_id uuid,
    target text NOT NULL,
    network text NOT NULL DEFAULT 'solana-mainnet',
    owner_wallet text NOT NULL,
    holder_rank integer NOT NULL,
    balance numeric NOT NULL DEFAULT 0,
    percentage numeric NOT NULL DEFAULT 0,
    scanned_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT security_radar_holder_snapshots_rank_check CHECK (holder_rank BETWEEN 1 AND 5),
    CONSTRAINT security_radar_holder_snapshots_percentage_check CHECK (percentage >= 0),
    CONSTRAINT security_radar_holder_snapshots_scan_owner_unique UNIQUE (scan_id, owner_wallet)
);

CREATE INDEX IF NOT EXISTS idx_security_radar_holder_snapshots_owner_time
    ON security_radar_holder_snapshots (owner_wallet, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_radar_holder_snapshots_target_time
    ON security_radar_holder_snapshots (target, scanned_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_radar_holder_snapshots_owner_percentage
    ON security_radar_holder_snapshots (owner_wallet, percentage DESC, scanned_at DESC);

WITH source_accounts AS (
    SELECT
        v.id AS source_verdict_id,
        v.target,
        COALESCE(NULLIF(v.network,''),'solana-mainnet') AS network,
        v.created_at AS scanned_at,
        account.value AS account
    FROM security_radar_verdicts v
    CROSS JOIN LATERAL jsonb_array_elements(
        CASE
            WHEN jsonb_typeof(v.signals #> '{holder_role_analysis,top_accounts}') = 'array'
                THEN v.signals #> '{holder_role_analysis,top_accounts}'
            ELSE '[]'::jsonb
        END
    ) AS account(value)
    WHERE v.module_id='holder_concentration'
), aggregated AS (
    SELECT
        source_verdict_id,
        target,
        network,
        scanned_at,
        btrim(account->>'owner_wallet') AS owner_wallet,
        SUM(COALESCE(NULLIF(account->>'balance','')::numeric,0)) AS balance,
        SUM(COALESCE(
            NULLIF(account->>'circulating_percentage','')::numeric,
            NULLIF(account->>'raw_percentage','')::numeric,
            0
        )) AS percentage
    FROM source_accounts
    WHERE btrim(COALESCE(account->>'owner_wallet','')) <> ''
      AND COALESCE(NULLIF(account->>'excluded_from_holder_risk','')::boolean,false)=false
    GROUP BY source_verdict_id,target,network,scanned_at,btrim(account->>'owner_wallet')
), ranked AS (
    SELECT *, ROW_NUMBER() OVER (
        PARTITION BY source_verdict_id
        ORDER BY percentage DESC, balance DESC, owner_wallet
    ) AS holder_rank
    FROM aggregated
)
INSERT INTO security_radar_holder_snapshots
    (scan_id,source_verdict_id,target,network,owner_wallet,holder_rank,balance,percentage,scanned_at,created_at)
SELECT
    'verdict:'||source_verdict_id::text,
    source_verdict_id,
    target,
    network,
    owner_wallet,
    holder_rank,
    balance,
    percentage,
    scanned_at,
    now()
FROM ranked
WHERE holder_rank <= 5
ON CONFLICT (scan_id,owner_wallet) DO NOTHING;
