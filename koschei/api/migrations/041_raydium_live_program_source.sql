DO $$
DECLARE
  canonical_raydium_program CONSTANT TEXT := '675kPX9MHTjS2zt1qfr1NYHuzeLXfQM9H24wFSUt1Mp8';
  legacy_raydium_program CONSTANT TEXT := '675kPX9MHTjS2zt1qfr1NYhd1B9M9QGK6cEcDDCo2t9';
  legacy_raydium_source CONSTANT TEXT := '675kPX9MHTjS2zt1qfr1NY5Wwrzj4mWjU7VtXv9syS2';
BEGIN
  IF to_regclass('public.security_radar_sources') IS NULL THEN
    RETURN;
  END IF;

  WITH ranked AS (
    SELECT
      id,
      row_number() OVER (
        ORDER BY
          CASE
            WHEN address = canonical_raydium_program OR target = canonical_raydium_program THEN 0
            ELSE 1
          END,
          updated_at DESC,
          created_at DESC,
          id
      ) AS row_rank
    FROM public.security_radar_sources
    WHERE module_id = 'raydium_pool_guardian'
      AND COALESCE(NULLIF(network, ''), 'solana-mainnet') = 'solana-mainnet'
      AND (
        address IN (canonical_raydium_program, legacy_raydium_program, legacy_raydium_source)
        OR target IN (canonical_raydium_program, legacy_raydium_program, legacy_raydium_source)
      )
  )
  DELETE FROM public.security_radar_sources AS source
  USING ranked
  WHERE source.id = ranked.id
    AND ranked.row_rank > 1;

  UPDATE public.security_radar_sources
  SET
    label = 'Raydium Pool Guardian',
    address = canonical_raydium_program,
    network = 'solana-mainnet',
    enabled = true,
    name = 'Raydium Pool Guardian',
    target = canonical_raydium_program,
    target_type = 'program',
    provider = 'alchemy',
    watch_mode = 'polling',
    updated_at = now()
  WHERE module_id = 'raydium_pool_guardian'
    AND COALESCE(NULLIF(network, ''), 'solana-mainnet') = 'solana-mainnet'
    AND (
      address IN (canonical_raydium_program, legacy_raydium_program, legacy_raydium_source)
      OR target IN (canonical_raydium_program, legacy_raydium_program, legacy_raydium_source)
    );

  IF NOT EXISTS (
    SELECT 1
    FROM public.security_radar_sources
    WHERE module_id = 'raydium_pool_guardian'
      AND address = canonical_raydium_program
      AND COALESCE(NULLIF(network, ''), 'solana-mainnet') = 'solana-mainnet'
  ) THEN
    INSERT INTO public.security_radar_sources (
      module_id,
      label,
      address,
      network,
      enabled,
      name,
      target,
      target_type,
      provider,
      watch_mode,
      created_at,
      updated_at
    )
    VALUES (
      'raydium_pool_guardian',
      'Raydium Pool Guardian',
      canonical_raydium_program,
      'solana-mainnet',
      true,
      'Raydium Pool Guardian',
      canonical_raydium_program,
      'program',
      'alchemy',
      'polling',
      now(),
      now()
    );
  END IF;
END $$;
