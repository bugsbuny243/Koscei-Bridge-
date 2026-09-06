-- Reconcile stale ARVIS processing rows that may otherwise remain stuck forever.
UPDATE arvis_stream_processing p
SET status = 'completed',
    processed_at = COALESCE(p.processed_at, now()),
    last_error = 'reconciled_final_verdict_exists',
    updated_at = now()
WHERE p.status = 'processing'
  AND p.updated_at < now() - interval '5 minutes'
  AND EXISTS (
    SELECT 1
    FROM security_radar_verdicts v
    WHERE v.module_id = 'final_verdict_engine'
      AND v.signed = true
      AND COALESCE(v.signals->>'source_stream_event_id','') = p.stream_event_id::text
  );

UPDATE arvis_stream_processing p
SET status = CASE WHEN p.attempts >= 3 THEN 'exhausted' ELSE 'failed' END,
    last_error = 'recovered stale processing lease',
    updated_at = CASE
                   WHEN p.attempts >= 5 THEN now()
                   WHEN p.attempts >= 3 THEN now() - interval '31 minutes'
                   ELSE now() - interval '1 minute'
                 END
WHERE p.status = 'processing'
  AND p.updated_at < now() - interval '5 minutes'
  AND NOT EXISTS (
    SELECT 1
    FROM security_radar_verdicts v
    WHERE v.module_id = 'final_verdict_engine'
      AND v.signed = true
      AND COALESCE(v.signals->>'source_stream_event_id','') = p.stream_event_id::text
  );

-- Normalize the Pump.fun source row to the canonical launch program used by the live worker.
DO $$
DECLARE
  canonical_target constant text := '6EF8rrecthR5Dkzon8Nwu78hRvfCKubJ14M5uBEwF6P';
  canonical_id uuid;
BEGIN
  SELECT id INTO canonical_id
  FROM security_radar_sources
  WHERE module_id = 'pump_sybil_radar'
    AND target = canonical_target
  ORDER BY updated_at DESC
  LIMIT 1;

  IF canonical_id IS NULL THEN
    SELECT id INTO canonical_id
    FROM security_radar_sources
    WHERE module_id = 'pump_sybil_radar'
    ORDER BY updated_at DESC
    LIMIT 1;

    IF canonical_id IS NULL THEN
      INSERT INTO security_radar_sources (
        module_id,name,label,target,address,target_type,provider,watch_mode,network,enabled,
        last_seen_signature,last_seen_slot,created_at,updated_at
      ) VALUES (
        'pump_sybil_radar','Pump.fun Sybil Radar','Pump.fun Sybil Radar',
        canonical_target,canonical_target,'program','alchemy','polling','solana-mainnet',true,
        NULL,NULL,now(),now()
      )
      RETURNING id INTO canonical_id;
    ELSE
      UPDATE security_radar_sources
      SET target = canonical_target,
          address = canonical_target,
          name = 'Pump.fun Sybil Radar',
          label = 'Pump.fun Sybil Radar',
          target_type = 'program',
          provider = 'alchemy',
          watch_mode = 'polling',
          network = 'solana-mainnet',
          enabled = true,
          last_seen_signature = NULL,
          last_seen_slot = NULL,
          updated_at = now()
      WHERE id = canonical_id;
    END IF;
  END IF;

  DELETE FROM security_radar_sources
  WHERE module_id = 'pump_sybil_radar'
    AND id <> canonical_id;

  UPDATE security_radar_sources
  SET target = canonical_target,
      address = canonical_target,
      name = 'Pump.fun Sybil Radar',
      label = 'Pump.fun Sybil Radar',
      target_type = 'program',
      provider = 'alchemy',
      watch_mode = 'polling',
      network = 'solana-mainnet',
      enabled = true,
      updated_at = now()
  WHERE id = canonical_id;
END $$;
