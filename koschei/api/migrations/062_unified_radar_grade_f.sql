ALTER TABLE IF EXISTS security_unified_radar_verdicts
    DROP CONSTRAINT IF EXISTS security_unified_radar_grade_check;

ALTER TABLE IF EXISTS security_unified_radar_verdicts
    ADD CONSTRAINT security_unified_radar_grade_check
    CHECK (grade IN ('-','A','B','C','D','E','F'));
