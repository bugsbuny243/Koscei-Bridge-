CREATE INDEX IF NOT EXISTS security_radar_stream_events_module_created_idx
ON security_radar_stream_events (module_id, created_at DESC);

CREATE INDEX IF NOT EXISTS security_radar_stream_events_module_evidence_created_idx
ON security_radar_stream_events (module_id, evidence_quality, created_at DESC);

CREATE INDEX IF NOT EXISTS security_radar_stream_events_target_queue_idx
ON security_radar_stream_events (target_type, module_id, created_at ASC)
WHERE COALESCE(target,'') <> '';

CREATE INDEX IF NOT EXISTS security_radar_processing_status_updated_idx
ON arvis_stream_processing (status, updated_at DESC, attempts);
