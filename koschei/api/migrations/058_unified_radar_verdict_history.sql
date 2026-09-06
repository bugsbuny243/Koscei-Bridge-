CREATE TABLE IF NOT EXISTS security_unified_radar_verdicts (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network text NOT NULL DEFAULT 'solana-mainnet',
    target_kind text NOT NULL,
    target_id text NOT NULL,
    grade text NOT NULL DEFAULT '-',
    verdict text NOT NULL,
    ruleset_version text NOT NULL,
    actor_ruleset_version text NOT NULL,
    signed boolean NOT NULL DEFAULT false,
    signature text,
    fingerprint text NOT NULL,
    triggered_rules jsonb NOT NULL DEFAULT '[]'::jsonb,
    watch_flags jsonb NOT NULL DEFAULT '[]'::jsonb,
    decision_path jsonb NOT NULL DEFAULT '[]'::jsonb,
    behavior_signals jsonb NOT NULL DEFAULT '[]'::jsonb,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    scan_count bigint NOT NULL DEFAULT 1,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT security_unified_radar_grade_check
        CHECK (grade IN ('-','A','B','C','D','E')),
    CONSTRAINT security_unified_radar_nonempty_check
        CHECK (
            btrim(network) <> '' AND
            btrim(target_kind) <> '' AND
            btrim(target_id) <> '' AND
            btrim(verdict) <> '' AND
            btrim(ruleset_version) <> '' AND
            btrim(actor_ruleset_version) <> '' AND
            btrim(fingerprint) <> ''
        ),
    CONSTRAINT security_unified_radar_fingerprint_unique UNIQUE (fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_security_unified_radar_target_time
    ON security_unified_radar_verdicts (network,target_kind,target_id,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_unified_radar_grade_time
    ON security_unified_radar_verdicts (grade,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_unified_radar_ruleset_time
    ON security_unified_radar_verdicts (ruleset_version,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_unified_radar_signature
    ON security_unified_radar_verdicts (signature)
    WHERE signature IS NOT NULL AND btrim(signature) <> '';
