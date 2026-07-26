-- Radar retention archive staging ledger (release gate #699).
--
-- Source deletion is permitted only through the retention worker's
-- archive/verify/delete statement. The final archive sink remains external to
-- this migration; exported_at and export_ref record destination verification.

CREATE TABLE IF NOT EXISTS radar_retention_runs (
    id                  uuid PRIMARY KEY,
    started_at          timestamptz NOT NULL DEFAULT now(),
    finished_at         timestamptz,
    cutoff              timestamptz NOT NULL,
    status              text        NOT NULL DEFAULT 'running',
    selected_rows       bigint      NOT NULL DEFAULT 0,
    archived_rows       bigint      NOT NULL DEFAULT 0,
    verified_rows       bigint      NOT NULL DEFAULT 0,
    deleted_rows        bigint      NOT NULL DEFAULT 0,
    checksum_mismatches bigint      NOT NULL DEFAULT 0,
    pruned_rows         bigint      NOT NULL DEFAULT 0,
    detail              jsonb       NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT radar_retention_runs_status_check
        CHECK (status IN ('running', 'completed', 'halted', 'failed')),
    CONSTRAINT radar_retention_runs_counts_check
        CHECK (
            selected_rows >= 0 AND archived_rows >= 0 AND verified_rows >= 0
            AND deleted_rows >= 0 AND checksum_mismatches >= 0 AND pruned_rows >= 0
        )
);

CREATE INDEX IF NOT EXISTS radar_retention_runs_started_idx
    ON radar_retention_runs (started_at DESC);

CREATE TABLE IF NOT EXISTS radar_retention_archive (
    id            bigserial PRIMARY KEY,
    run_id        uuid        NOT NULL REFERENCES radar_retention_runs(id) ON DELETE RESTRICT,
    source_table  text        NOT NULL,
    source_id     text        NOT NULL,
    row_checksum  text        NOT NULL,
    payload       jsonb       NOT NULL,
    archived_at   timestamptz NOT NULL DEFAULT now(),
    exported_at   timestamptz,
    export_ref    text,
    CONSTRAINT radar_retention_archive_unique UNIQUE (source_table, source_id),
    CONSTRAINT radar_retention_archive_checksum_check
        CHECK (row_checksum ~ '^[0-9a-f]{64}$'),
    CONSTRAINT radar_retention_archive_export_check
        CHECK (exported_at IS NULL OR NULLIF(btrim(export_ref), '') IS NOT NULL)
);

CREATE INDEX IF NOT EXISTS radar_retention_archive_pending_export_idx
    ON radar_retention_archive (archived_at)
    WHERE exported_at IS NULL;

CREATE INDEX IF NOT EXISTS radar_retention_archive_exported_idx
    ON radar_retention_archive (exported_at)
    WHERE exported_at IS NOT NULL;

CREATE INDEX IF NOT EXISTS radar_retention_archive_run_idx
    ON radar_retention_archive (run_id);
