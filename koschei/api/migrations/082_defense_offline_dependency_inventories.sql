CREATE TABLE IF NOT EXISTS defense_offline_dependency_inventories (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    inventory_ref text NOT NULL UNIQUE,
    inventory_version text NOT NULL,
    worker_id text NOT NULL,
    worker_image_digest text NOT NULL,
    inventory_path text NOT NULL,
    vendor_path text NOT NULL,
    cargo_config_path text NOT NULL,
    cargo_manifest_hash text NOT NULL,
    cargo_lock_hash text NOT NULL,
    cargo_config_hash text NOT NULL,
    package_name text NOT NULL,
    package_version text NOT NULL,
    file_manifest jsonb NOT NULL,
    file_count integer NOT NULL,
    total_bytes bigint NOT NULL,
    vendor_tree_hash text NOT NULL,
    inventory_hash text NOT NULL,
    evidence_status text NOT NULL,
    limitations jsonb NOT NULL DEFAULT '[]'::jsonb,
    network_access boolean NOT NULL DEFAULT false,
    dependency_resolution boolean NOT NULL DEFAULT false,
    verdict_authority boolean NOT NULL DEFAULT false,
    observed_at timestamptz NOT NULL,
    created_by text NOT NULL DEFAULT 'defense-worker',
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT defense_offline_dependency_inventories_ref_format CHECK (inventory_ref ~ '^KODI1-[0-9a-f]{32}$'),
    CONSTRAINT defense_offline_dependency_inventories_version_format CHECK (inventory_version ~ '^v[0-9]+\.[0-9]+\.[0-9]+$'),
    CONSTRAINT defense_offline_dependency_inventories_image_hash CHECK (worker_image_digest ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_offline_dependency_inventories_fixed_paths CHECK (
        inventory_path = '/opt/koschei/offline-deps/inventory.json'
        AND vendor_path = '/opt/koschei/offline-deps/vendor'
        AND cargo_config_path = '/opt/koschei/offline-deps/cargo-config.toml'
    ),
    CONSTRAINT defense_offline_dependency_inventories_manifest_hash CHECK (cargo_manifest_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_offline_dependency_inventories_lock_hash CHECK (cargo_lock_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_offline_dependency_inventories_config_hash CHECK (cargo_config_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_offline_dependency_inventories_package CHECK (package_name = 'litesvm' AND package_version = '0.6.1'),
    CONSTRAINT defense_offline_dependency_inventories_manifest_array CHECK (jsonb_typeof(file_manifest) = 'array'),
    CONSTRAINT defense_offline_dependency_inventories_totals CHECK (file_count > 0 AND total_bytes >= 0 AND jsonb_array_length(file_manifest) = file_count),
    CONSTRAINT defense_offline_dependency_inventories_tree_hash CHECK (vendor_tree_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_offline_dependency_inventories_inventory_hash CHECK (inventory_hash ~ '^sha256:[0-9a-f]{64}$'),
    CONSTRAINT defense_offline_dependency_inventories_status CHECK (evidence_status IN ('verified','rejected')),
    CONSTRAINT defense_offline_dependency_inventories_limitations_array CHECK (jsonb_typeof(limitations) = 'array'),
    CONSTRAINT defense_offline_dependency_inventories_boundaries CHECK (
        network_access = false AND dependency_resolution = false AND verdict_authority = false
    ),
    CONSTRAINT defense_offline_dependency_inventories_identity_nonempty CHECK (btrim(worker_id) <> ''),
    CONSTRAINT defense_offline_dependency_inventories_identity_unique UNIQUE (worker_id, worker_image_digest, inventory_hash)
);

CREATE INDEX IF NOT EXISTS defense_offline_dependency_inventories_worker_idx
    ON defense_offline_dependency_inventories (worker_id, observed_at DESC);
CREATE INDEX IF NOT EXISTS defense_offline_dependency_inventories_image_idx
    ON defense_offline_dependency_inventories (worker_image_digest, observed_at DESC);
CREATE INDEX IF NOT EXISTS defense_offline_dependency_inventories_hash_idx
    ON defense_offline_dependency_inventories (inventory_hash, observed_at DESC);

DROP TRIGGER IF EXISTS defense_offline_dependency_inventories_immutable ON defense_offline_dependency_inventories;
CREATE TRIGGER defense_offline_dependency_inventories_immutable
BEFORE UPDATE OR DELETE ON defense_offline_dependency_inventories
FOR EACH ROW EXECUTE FUNCTION reject_defense_runtime_mutation();
