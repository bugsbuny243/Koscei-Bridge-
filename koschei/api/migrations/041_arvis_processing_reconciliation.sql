UPDATE arvis_stream_processing p
SET status = 'completed',
    processed_at = COALESCE(p.processed_at, now()),
    last_error = 'reconciled_final_verdict_exists',
    updated_at = now()
WHERE p.status IN ('failed','exhausted')
  AND EXISTS (
    SELECT 1
    FROM security_radar_verdicts v
    WHERE v.module_id = 'final_verdict_engine'
      AND v.signed = true
      AND COALESCE(v.signals->>'source_stream_event_id','') = p.stream_event_id::text
  );

UPDATE arvis_stream_processing
SET attempts = LEAST(attempts, 3),
    updated_at = now() - interval '31 minutes'
WHERE status = 'exhausted'
  AND attempts < 5;
