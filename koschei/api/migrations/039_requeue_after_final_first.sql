UPDATE arvis_stream_processing
SET attempts = 0,
    status = 'failed',
    updated_at = now() - interval '1 minute'
WHERE status = 'failed';
