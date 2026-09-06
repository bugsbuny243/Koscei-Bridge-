WITH ranked_stream_verdicts AS (
    SELECT
        ctid,
        row_number() OVER (
            PARTITION BY signals->>'source_stream_event_id', module_id
            ORDER BY created_at DESC, id DESC
        ) AS row_num
    FROM security_radar_verdicts
    WHERE source='arvis_stream'
      AND COALESCE(signals->>'source_stream_event_id','') <> ''
)
DELETE FROM security_radar_verdicts verdict
USING ranked_stream_verdicts ranked
WHERE verdict.ctid = ranked.ctid
  AND ranked.row_num > 1;

CREATE UNIQUE INDEX IF NOT EXISTS security_radar_verdicts_stream_event_module_uniq
ON security_radar_verdicts ((signals->>'source_stream_event_id'), module_id)
WHERE source='arvis_stream'
  AND COALESCE(signals->>'source_stream_event_id','') <> '';
