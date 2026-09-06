-- External radar-retention archive export ledger (release gate #699).
--
-- Retention and export are separate fail-closed operations with different
-- lifecycles. A parallel ledger keeps destination verification failures from
-- being confused with archive/delete failures in radar_retention_runs.

CREATE TABLE IF NOT EXISTS radar_retention_export_runs (
    id                  uuid PRIMARY KEY,
    started_at          timestamptz NOT NULL DEFAULT now(),
    finished_at         timestamptz,
    status              text        NOT NULL DEFAULT 'running',
    sink                 text        NOT NULL,
    selected_rows        bigint      NOT NULL DEFAULT 0,
    exported_rows        bigint      NOT NULL DEFAULT 0,
    object_count         bigint      NOT NULL DEFAULT 0,
    bytes_exported       bigint      NOT NULL DEFAULT 0,
    checksum_mismatches  bigint      NOT NULL DEFAULT 0,
    last_export_ref      text,
    error_message        text,
    detail               jsonb       NOT NULL DEFAULT '{}'::jsonb,
    CONSTRAINT radar_retention_export_runs_status_check
        CHECK (status IN ('running', 'completed', 'failed')),
    CONSTRAINT radar_retention_export_runs_counts_check
        CHECK (
            selected_rows >= 0 AND exported_rows >= 0
            AND object_count >= 0 AND bytes_exported >= 0
            AND checksum_mismatches >= 0
        )
);

CREATE INDEX IF NOT EXISTS radar_retention_export_runs_started_idx
    ON radar_retention_export_runs (started_at DESC);

CREATE INDEX IF NOT EXISTS radar_retention_export_runs_status_idx
    ON radar_retention_export_runs (status, started_at DESC);
