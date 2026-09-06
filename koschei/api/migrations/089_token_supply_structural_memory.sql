-- Persist the latest verified token supply independently from holder and
-- authority observations. Supply is change-monitoring evidence only; it is not
-- part of the structural risk floor.

CREATE TABLE IF NOT EXISTS public.token_structural_signals (
    target text NOT NULL,
    network text NOT NULL,
    largest_holder_pct integer NOT NULL DEFAULT 0 CHECK (largest_holder_pct BETWEEN 0 AND 100),
    top10_holder_pct integer NOT NULL DEFAULT 0 CHECK (top10_holder_pct BETWEEN 0 AND 100),
    has_holder_data boolean NOT NULL DEFAULT false,
    mint_authority_present boolean NOT NULL DEFAULT false,
    freeze_authority_present boolean NOT NULL DEFAULT false,
    has_authority_data boolean NOT NULL DEFAULT false,
    holder_observed_at timestamptz,
    authority_observed_at timestamptz,
    launch_forensics_risk integer NOT NULL DEFAULT 0,
    launch_forensics_observed_at timestamptz,
    token_supply double precision,
    has_supply_data boolean NOT NULL DEFAULT false,
    supply_observed_at timestamptz,
    observed_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (target, network)
);

ALTER TABLE public.token_structural_signals
    ADD COLUMN IF NOT EXISTS token_supply double precision,
    ADD COLUMN IF NOT EXISTS has_supply_data boolean NOT NULL DEFAULT false,
    ADD COLUMN IF NOT EXISTS supply_observed_at timestamptz;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1
        FROM pg_constraint
        WHERE conname = 'token_structural_signals_supply_finite_nonnegative'
          AND conrelid = 'public.token_structural_signals'::regclass
    ) THEN
        ALTER TABLE public.token_structural_signals
            ADD CONSTRAINT token_structural_signals_supply_finite_nonnegative
            CHECK (
                token_supply IS NULL
                OR (
                    token_supply >= 0
                    AND token_supply <> 'Infinity'::double precision
                    AND token_supply <> '-Infinity'::double precision
                    AND token_supply <> 'NaN'::double precision
                )
            );
    END IF;
END $$;

WITH verified_supply AS (
    SELECT DISTINCT ON (v.target, v.network)
        v.target,
        v.network,
        (btrim(v.signals->>'token_supply'))::double precision AS token_supply,
        v.created_at AS supply_observed_at
    FROM public.security_radar_verdicts v
    WHERE v.module_id = 'holder_concentration'
      AND v.signed = true
      AND btrim(COALESCE(v.signature, '')) <> ''
      AND btrim(COALESCE(v.target, '')) <> ''
      AND v.signals ? 'token_supply'
      AND btrim(COALESCE(v.signals->>'token_supply', ''))
          ~ '^(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$'
      AND (
          COALESCE(v.signals->>'verified_evidence', 'false') = 'true'
          OR COALESCE(v.signals->>'real_onchain_evidence', 'false') = 'true'
          OR COALESCE(v.signals->>'real_offchain_evidence', 'false') = 'true'
      )
    ORDER BY v.target, v.network, v.created_at DESC, v.id DESC
)
INSERT INTO public.token_structural_signals
    (target, network, token_supply, has_supply_data, supply_observed_at, observed_at, updated_at)
SELECT
    target, network, token_supply, true, supply_observed_at, supply_observed_at, now()
FROM verified_supply
ON CONFLICT (target, network) DO UPDATE SET
    token_supply = CASE
        WHEN COALESCE(EXCLUDED.supply_observed_at, '-infinity'::timestamptz)
             >= COALESCE(token_structural_signals.supply_observed_at, '-infinity'::timestamptz)
        THEN EXCLUDED.token_supply
        ELSE token_structural_signals.token_supply
    END,
    has_supply_data = token_structural_signals.has_supply_data OR EXCLUDED.has_supply_data,
    supply_observed_at = GREATEST(
        token_structural_signals.supply_observed_at,
        EXCLUDED.supply_observed_at
    ),
    observed_at = GREATEST(
        token_structural_signals.observed_at,
        EXCLUDED.observed_at
    ),
    updated_at = now();

CREATE INDEX IF NOT EXISTS idx_token_structural_signals_supply_observed
    ON public.token_structural_signals (supply_observed_at DESC)
    WHERE has_supply_data = true;
