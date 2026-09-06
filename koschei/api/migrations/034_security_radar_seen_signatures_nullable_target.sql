DO $$
BEGIN
  IF EXISTS (
    SELECT 1
    FROM information_schema.columns
    WHERE table_schema = 'public'
      AND table_name = 'security_radar_seen_signatures'
      AND column_name = 'source_target'
  ) THEN
    ALTER TABLE security_radar_seen_signatures
      ALTER COLUMN source_target DROP NOT NULL;
  END IF;
END $$;
