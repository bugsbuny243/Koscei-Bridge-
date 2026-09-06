-- Canonical architecture: ACTOR_INVESTIGATION_ENGINE.md sections 3, 4 and 6.
-- security_actor_evidence is both the signed evidence ledger and the persistent
-- actor index: address -> role, mint, evidence, timestamp. Raw-event retention
-- must never delete rows from this table.
CREATE TABLE IF NOT EXISTS security_actor_evidence (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network text NOT NULL DEFAULT 'solana-mainnet',
    actor_wallet text NOT NULL,
    actor_role text NOT NULL DEFAULT 'actor',
    counterpart_kind text NOT NULL,
    counterpart_id text NOT NULL,
    relation text NOT NULL,
    verification_status text NOT NULL DEFAULT 'observed',
    evidence_key text NOT NULL,
    source text NOT NULL DEFAULT 'koschei',
    signature text,
    slot bigint,
    observed_at timestamptz NOT NULL DEFAULT now(),
    first_observed_at timestamptz NOT NULL DEFAULT now(),
    last_observed_at timestamptz NOT NULL DEFAULT now(),
    source_wallet text NOT NULL DEFAULT '',
    destination_wallet text NOT NULL DEFAULT '',
    program text NOT NULL DEFAULT '',
    amount_native numeric NOT NULL DEFAULT 0,
    token_mint text,
    token_amount numeric NOT NULL DEFAULT 0,
    occurrence_count bigint NOT NULL DEFAULT 1,
    metadata jsonb NOT NULL DEFAULT '{}'::jsonb,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT security_actor_evidence_status_check
        CHECK (verification_status IN ('verified','observed','inferred','unverified')),
    CONSTRAINT security_actor_evidence_nonempty_check
        CHECK (
            btrim(actor_wallet) <> '' AND
            btrim(actor_role) <> '' AND
            btrim(counterpart_kind) <> '' AND
            btrim(counterpart_id) <> '' AND
            btrim(relation) <> '' AND
            btrim(evidence_key) <> '' AND
            btrim(source) <> ''
        ),
    CONSTRAINT security_actor_evidence_amounts_check
        CHECK (amount_native >= 0 AND token_amount >= 0 AND occurrence_count >= 1),
    CONSTRAINT security_actor_evidence_time_check
        CHECK (first_observed_at <= last_observed_at),
    CONSTRAINT security_actor_evidence_verified_line_check
        CHECK (
            verification_status <> 'verified' OR
            relation NOT IN (
                'direct_sol_transfer_in','direct_sol_transfer_out',
                'direct_token_transfer_in','direct_token_transfer_out',
                'liquidity_remove_activity'
            ) OR (
                btrim(source_wallet) <> '' AND
                btrim(destination_wallet) <> '' AND
                btrim(program) <> '' AND
                signature IS NOT NULL AND btrim(signature) <> '' AND
                slot IS NOT NULL AND slot > 0
            )
        ),
    CONSTRAINT security_actor_evidence_unique
        UNIQUE (network,actor_wallet,counterpart_kind,counterpart_id,relation,source,evidence_key)
);

-- Safe for a partially applied development branch.
ALTER TABLE security_actor_evidence ADD COLUMN IF NOT EXISTS actor_role text NOT NULL DEFAULT 'actor';
ALTER TABLE security_actor_evidence ADD COLUMN IF NOT EXISTS first_observed_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE security_actor_evidence ADD COLUMN IF NOT EXISTS last_observed_at timestamptz NOT NULL DEFAULT now();
ALTER TABLE security_actor_evidence ADD COLUMN IF NOT EXISTS source_wallet text NOT NULL DEFAULT '';
ALTER TABLE security_actor_evidence ADD COLUMN IF NOT EXISTS destination_wallet text NOT NULL DEFAULT '';
ALTER TABLE security_actor_evidence ADD COLUMN IF NOT EXISTS program text NOT NULL DEFAULT '';

-- Normalize every evidence line at the database boundary. Direct transfer
-- direction and program are deterministic from the parsed relation. A claimed
-- VERIFIED liquidity removal is downgraded to OBSERVED until the collector has
-- resolved the destination pool/account and program as well as signer/mint.
CREATE OR REPLACE FUNCTION normalize_security_actor_evidence_line()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    relation_value text;
    metadata_program text;
    metadata_destination text;
BEGIN
    NEW.actor_wallet := btrim(COALESCE(NEW.actor_wallet,''));
    NEW.counterpart_kind := btrim(COALESCE(NEW.counterpart_kind,''));
    NEW.counterpart_id := btrim(COALESCE(NEW.counterpart_id,''));
    NEW.relation := btrim(COALESCE(NEW.relation,''));
    NEW.actor_role := btrim(COALESCE(NULLIF(NEW.actor_role,''),NULLIF(NEW.metadata->>'actor_role',''),'actor'));
    NEW.source_wallet := btrim(COALESCE(NEW.source_wallet,''));
    NEW.destination_wallet := btrim(COALESCE(NEW.destination_wallet,''));
    NEW.program := btrim(COALESCE(NEW.program,''));
    relation_value := lower(NEW.relation);
    metadata_program := btrim(COALESCE(NEW.metadata->>'program',''));
    metadata_destination := btrim(COALESCE(
        NULLIF(NEW.metadata->>'destination_wallet',''),
        NULLIF(NEW.metadata->>'pool_wallet',''),
        NULLIF(NEW.metadata->>'pool_account',''),
        ''
    ));

    IF relation_value IN ('direct_sol_transfer_out','direct_token_transfer_out') THEN
        NEW.source_wallet := COALESCE(NULLIF(NEW.source_wallet,''),NEW.actor_wallet);
        NEW.destination_wallet := COALESCE(NULLIF(NEW.destination_wallet,''),NEW.counterpart_id);
    ELSIF relation_value IN ('direct_sol_transfer_in','direct_token_transfer_in') THEN
        NEW.source_wallet := COALESCE(NULLIF(NEW.source_wallet,''),NEW.counterpart_id);
        NEW.destination_wallet := COALESCE(NULLIF(NEW.destination_wallet,''),NEW.actor_wallet);
    ELSIF relation_value='liquidity_remove_activity' THEN
        NEW.source_wallet := COALESCE(NULLIF(NEW.source_wallet,''),NEW.actor_wallet);
        NEW.destination_wallet := COALESCE(NULLIF(NEW.destination_wallet,''),metadata_destination);
    END IF;

    IF NEW.program='' THEN
        NEW.program := CASE
            WHEN relation_value IN ('direct_sol_transfer_in','direct_sol_transfer_out') THEN 'system'
            WHEN relation_value IN ('direct_token_transfer_in','direct_token_transfer_out','dominant_holder_of') THEN 'spl-token'
            WHEN relation_value='created_token' THEN COALESCE(NULLIF(metadata_program,''),'pump.fun')
            ELSE metadata_program
        END;
    END IF;

    NEW.first_observed_at := COALESCE(NEW.first_observed_at,NEW.observed_at,now());
    NEW.last_observed_at := COALESCE(NEW.last_observed_at,NEW.observed_at,now());
    IF TG_OP='UPDATE' THEN
        NEW.first_observed_at := LEAST(OLD.first_observed_at,NEW.first_observed_at);
        NEW.last_observed_at := GREATEST(OLD.last_observed_at,NEW.last_observed_at,NEW.observed_at);
    END IF;
    NEW.observed_at := NEW.last_observed_at;

    IF relation_value='liquidity_remove_activity'
       AND NEW.verification_status='verified'
       AND (
            NEW.source_wallet='' OR NEW.destination_wallet='' OR NEW.program='' OR
            NEW.signature IS NULL OR btrim(NEW.signature)='' OR NEW.slot IS NULL OR NEW.slot<=0 OR
            lower(COALESCE(NEW.metadata->>'actor_signed','false'))<>'true' OR
            lower(COALESCE(NEW.metadata->>'creator_role_observed','false'))<>'true' OR
            COALESCE(NEW.token_mint,'')=''
       ) THEN
        NEW.verification_status := 'observed';
        NEW.metadata := COALESCE(NEW.metadata,'{}'::jsonb) || jsonb_build_object(
            'verification_downgrade_reason',
            'liquidity removal lacks a complete signer, creator-linked mint, pool destination or program evidence line'
        );
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS security_actor_evidence_normalize_line ON security_actor_evidence;
CREATE TRIGGER security_actor_evidence_normalize_line
BEFORE INSERT OR UPDATE ON security_actor_evidence
FOR EACH ROW
EXECUTE FUNCTION normalize_security_actor_evidence_line();

CREATE INDEX IF NOT EXISTS idx_security_actor_evidence_actor_time
    ON security_actor_evidence (network,actor_wallet,last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_actor_evidence_actor_role_mint
    ON security_actor_evidence (network,actor_wallet,actor_role,token_mint,last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_actor_evidence_counterpart_time
    ON security_actor_evidence (network,counterpart_kind,counterpart_id,last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_actor_evidence_relation_time
    ON security_actor_evidence (network,relation,last_observed_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_actor_evidence_signature
    ON security_actor_evidence (signature)
    WHERE signature IS NOT NULL AND btrim(signature) <> '';
CREATE INDEX IF NOT EXISTS idx_security_actor_evidence_token_mint
    ON security_actor_evidence (token_mint,last_observed_at DESC)
    WHERE token_mint IS NOT NULL AND btrim(token_mint) <> '';

-- Seed persistent creator/deployer memory from existing Koschei sensor history.
-- PumpPortal's source-reported creator metadata remains OBSERVED. It becomes
-- VERIFIED only when an explicit parsed creator relation flag is present.
WITH creator_rows AS (
    SELECT
        COALESCE(NULLIF(e.network,''),'solana-mainnet') AS network,
        COALESCE(
            NULLIF(btrim(e.signals->>'creator_wallet'),''),
            NULLIF(btrim(e.signals->>'deployer_wallet'),'')
        ) AS actor_wallet,
        e.target AS mint,
        min(e.created_at) AS first_seen_at,
        max(e.created_at) AS last_seen_at,
        count(*)::bigint AS occurrence_count,
        (array_agg(NULLIF(btrim(e.signature),'') ORDER BY e.created_at DESC)
            FILTER (WHERE e.signature IS NOT NULL AND btrim(e.signature)<>''))[1] AS signature,
        max(e.slot) AS slot,
        bool_or(
            lower(COALESCE(e.signals->>'creator_relation_verified','false'))='true' OR
            lower(COALESCE(e.signals->>'launch_transaction_parsed','false'))='true'
        ) AS creator_relation_verified
    FROM security_radar_events e
    WHERE e.target_type='token'
      AND btrim(COALESCE(e.target,''))<>''
      AND COALESCE(
            NULLIF(btrim(e.signals->>'creator_wallet'),''),
            NULLIF(btrim(e.signals->>'deployer_wallet'),'')
          ) IS NOT NULL
    GROUP BY COALESCE(NULLIF(e.network,''),'solana-mainnet'),
             COALESCE(NULLIF(btrim(e.signals->>'creator_wallet'),''),NULLIF(btrim(e.signals->>'deployer_wallet'),'')),
             e.target
)
INSERT INTO security_actor_evidence (
    network,actor_wallet,actor_role,counterpart_kind,counterpart_id,relation,
    verification_status,evidence_key,source,signature,slot,observed_at,
    first_observed_at,last_observed_at,program,token_mint,occurrence_count,metadata,
    created_at,updated_at
)
SELECT
    network,actor_wallet,'creator_deployer','token',mint,'created_token',
    CASE WHEN creator_relation_verified AND signature IS NOT NULL THEN 'verified' ELSE 'observed' END,
    'creator:'||mint,'security_radar_events',signature,slot,last_seen_at,
    first_seen_at,last_seen_at,'pump.fun',mint,occurrence_count,
    jsonb_build_object(
        'actor_role','creator_deployer',
        'creator_relation_scope',CASE WHEN creator_relation_verified THEN 'parsed creator relation' ELSE 'source-reported creator/deployer observation' END,
        'persistent_actor_index',true
    ),
    first_seen_at,now()
FROM creator_rows
ON CONFLICT (network,actor_wallet,counterpart_kind,counterpart_id,relation,source,evidence_key)
DO UPDATE SET
    verification_status=CASE
        WHEN security_actor_evidence.verification_status='verified' OR EXCLUDED.verification_status='verified' THEN 'verified'
        ELSE 'observed'
    END,
    signature=COALESCE(EXCLUDED.signature,security_actor_evidence.signature),
    slot=COALESCE(EXCLUDED.slot,security_actor_evidence.slot),
    first_observed_at=LEAST(security_actor_evidence.first_observed_at,EXCLUDED.first_observed_at),
    last_observed_at=GREATEST(security_actor_evidence.last_observed_at,EXCLUDED.last_observed_at),
    occurrence_count=GREATEST(security_actor_evidence.occurrence_count,EXCLUDED.occurrence_count),
    metadata=security_actor_evidence.metadata || EXCLUDED.metadata,
    updated_at=now();

-- Seed persistent dominant-holder observations. The 20% threshold is an
-- owner-resolved observation boundary, not an identity or wrongdoing claim.
WITH holder_rows AS (
    SELECT
        COALESCE(NULLIF(h.network,''),'solana-mainnet') AS network,
        btrim(h.owner_wallet) AS actor_wallet,
        h.target AS mint,
        min(h.scanned_at) AS first_seen_at,
        max(h.scanned_at) AS last_seen_at,
        count(*)::bigint AS occurrence_count,
        max(h.percentage)::double precision AS max_percentage,
        min(h.holder_rank) AS best_rank
    FROM security_radar_holder_snapshots h
    WHERE btrim(COALESCE(h.owner_wallet,''))<>''
      AND btrim(COALESCE(h.target,''))<>''
      AND h.percentage>=20
    GROUP BY COALESCE(NULLIF(h.network,''),'solana-mainnet'),btrim(h.owner_wallet),h.target
)
INSERT INTO security_actor_evidence (
    network,actor_wallet,actor_role,counterpart_kind,counterpart_id,relation,
    verification_status,evidence_key,source,observed_at,first_observed_at,last_observed_at,
    program,token_mint,occurrence_count,metadata,created_at,updated_at
)
SELECT
    network,actor_wallet,'dominant_holder','token',mint,'dominant_holder_of',
    'observed','holder:'||mint,'security_radar_holder_snapshots',last_seen_at,
    first_seen_at,last_seen_at,'spl-token',mint,occurrence_count,
    jsonb_build_object(
        'actor_role','dominant_holder',
        'max_holder_percentage',max_percentage,
        'best_holder_rank',best_rank,
        'owner_resolved',true,
        'persistent_actor_index',true
    ),
    first_seen_at,now()
FROM holder_rows
ON CONFLICT (network,actor_wallet,counterpart_kind,counterpart_id,relation,source,evidence_key)
DO UPDATE SET
    first_observed_at=LEAST(security_actor_evidence.first_observed_at,EXCLUDED.first_observed_at),
    last_observed_at=GREATEST(security_actor_evidence.last_observed_at,EXCLUDED.last_observed_at),
    occurrence_count=GREATEST(security_actor_evidence.occurrence_count,EXCLUDED.occurrence_count),
    metadata=security_actor_evidence.metadata || EXCLUDED.metadata,
    updated_at=now();

-- Persist future creator/deployer observations independently from raw retention.
CREATE OR REPLACE FUNCTION index_security_radar_event_actor()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    actor text;
    verified_relation boolean;
BEGIN
    IF NEW.target_type<>'token' OR btrim(COALESCE(NEW.target,''))='' THEN
        RETURN NEW;
    END IF;
    actor := COALESCE(
        NULLIF(btrim(NEW.signals->>'creator_wallet'),''),
        NULLIF(btrim(NEW.signals->>'deployer_wallet'),'')
    );
    IF actor IS NULL THEN
        RETURN NEW;
    END IF;
    verified_relation := (
        lower(COALESCE(NEW.signals->>'creator_relation_verified','false'))='true' OR
        lower(COALESCE(NEW.signals->>'launch_transaction_parsed','false'))='true'
    ) AND NEW.signature IS NOT NULL AND btrim(NEW.signature)<>'';

    INSERT INTO security_actor_evidence (
        network,actor_wallet,actor_role,counterpart_kind,counterpart_id,relation,
        verification_status,evidence_key,source,signature,slot,observed_at,
        first_observed_at,last_observed_at,program,token_mint,metadata
    ) VALUES (
        COALESCE(NULLIF(NEW.network,''),'solana-mainnet'),actor,'creator_deployer',
        'token',NEW.target,'created_token',CASE WHEN verified_relation THEN 'verified' ELSE 'observed' END,
        'creator:'||NEW.target,'security_radar_events',NULLIF(btrim(COALESCE(NEW.signature,'')),''),NEW.slot,
        COALESCE(NEW.block_time,NEW.created_at,now()),COALESCE(NEW.block_time,NEW.created_at,now()),
        COALESCE(NEW.block_time,NEW.created_at,now()),'pump.fun',NEW.target,
        jsonb_build_object(
            'actor_role','creator_deployer',
            'creator_relation_scope',CASE WHEN verified_relation THEN 'parsed creator relation' ELSE 'source-reported creator/deployer observation' END,
            'source_event_id',NEW.id,
            'persistent_actor_index',true
        )
    )
    ON CONFLICT (network,actor_wallet,counterpart_kind,counterpart_id,relation,source,evidence_key)
    DO UPDATE SET
        verification_status=CASE
            WHEN security_actor_evidence.verification_status='verified' OR EXCLUDED.verification_status='verified' THEN 'verified'
            ELSE 'observed'
        END,
        signature=COALESCE(EXCLUDED.signature,security_actor_evidence.signature),
        slot=COALESCE(EXCLUDED.slot,security_actor_evidence.slot),
        last_observed_at=GREATEST(security_actor_evidence.last_observed_at,EXCLUDED.last_observed_at),
        occurrence_count=security_actor_evidence.occurrence_count+1,
        metadata=security_actor_evidence.metadata || EXCLUDED.metadata,
        updated_at=now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS security_radar_events_actor_index ON security_radar_events;
CREATE TRIGGER security_radar_events_actor_index
AFTER INSERT ON security_radar_events
FOR EACH ROW
EXECUTE FUNCTION index_security_radar_event_actor();

-- Persist future owner-resolved dominant-holder observations independently from
-- raw snapshot retention. Historical dominance remains an OBSERVED fact even if
-- the current balance later changes.
CREATE OR REPLACE FUNCTION index_security_holder_actor()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF btrim(COALESCE(NEW.owner_wallet,''))='' OR btrim(COALESCE(NEW.target,''))='' OR NEW.percentage<20 THEN
        RETURN NEW;
    END IF;
    INSERT INTO security_actor_evidence (
        network,actor_wallet,actor_role,counterpart_kind,counterpart_id,relation,
        verification_status,evidence_key,source,observed_at,first_observed_at,last_observed_at,
        program,token_mint,metadata
    ) VALUES (
        COALESCE(NULLIF(NEW.network,''),'solana-mainnet'),btrim(NEW.owner_wallet),'dominant_holder',
        'token',NEW.target,'dominant_holder_of','observed','holder:'||NEW.target,
        'security_radar_holder_snapshots',NEW.scanned_at,NEW.scanned_at,NEW.scanned_at,
        'spl-token',NEW.target,
        jsonb_build_object(
            'actor_role','dominant_holder',
            'holder_percentage',NEW.percentage,
            'holder_rank',NEW.holder_rank,
            'owner_resolved',true,
            'source_snapshot_id',NEW.id,
            'persistent_actor_index',true
        )
    )
    ON CONFLICT (network,actor_wallet,counterpart_kind,counterpart_id,relation,source,evidence_key)
    DO UPDATE SET
        last_observed_at=GREATEST(security_actor_evidence.last_observed_at,EXCLUDED.last_observed_at),
        occurrence_count=security_actor_evidence.occurrence_count+1,
        metadata=security_actor_evidence.metadata || EXCLUDED.metadata,
        updated_at=now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS security_radar_holder_snapshots_actor_index ON security_radar_holder_snapshots;
CREATE TRIGGER security_radar_holder_snapshots_actor_index
AFTER INSERT ON security_radar_holder_snapshots
FOR EACH ROW
EXECUTE FUNCTION index_security_holder_actor();

CREATE TABLE IF NOT EXISTS security_threat_tracks (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    network text NOT NULL DEFAULT 'solana-mainnet',
    target_kind text NOT NULL DEFAULT 'wallet',
    target_id text NOT NULL,
    state text NOT NULL DEFAULT 'detected',
    created_token_count integer NOT NULL DEFAULT 0,
    dominant_holder_token_count integer NOT NULL DEFAULT 0,
    traded_token_count integer NOT NULL DEFAULT 0,
    related_actor_count integer NOT NULL DEFAULT 0,
    verified_evidence_count integer NOT NULL DEFAULT 0,
    observed_evidence_count integer NOT NULL DEFAULT 0,
    dossier jsonb NOT NULL DEFAULT '{}'::jsonb,
    first_seen_at timestamptz NOT NULL DEFAULT now(),
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    last_investigated_at timestamptz NOT NULL DEFAULT now(),
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT security_threat_tracks_state_check
        CHECK (state IN ('detected','tracked','correlated','verified','alerted')),
    CONSTRAINT security_threat_tracks_nonempty_check
        CHECK (btrim(target_kind) <> '' AND btrim(target_id) <> ''),
    CONSTRAINT security_threat_tracks_counts_check
        CHECK (
            created_token_count >= 0 AND
            dominant_holder_token_count >= 0 AND
            traded_token_count >= 0 AND
            related_actor_count >= 0 AND
            verified_evidence_count >= 0 AND
            observed_evidence_count >= 0
        ),
    CONSTRAINT security_threat_tracks_time_check
        CHECK (first_seen_at <= last_seen_at),
    CONSTRAINT security_threat_tracks_target_unique
        UNIQUE (network,target_kind,target_id)
);

-- Threat memory is monotonic even when separate workers race. A later partial
-- dossier may enrich a track but may not erase stronger state, counters or the
-- earliest/latest observation window already persisted.
CREATE OR REPLACE FUNCTION preserve_security_threat_track_history()
RETURNS trigger
LANGUAGE plpgsql
AS $$
DECLARE
    old_rank integer;
    new_rank integer;
BEGIN
    old_rank := CASE OLD.state
        WHEN 'detected' THEN 1
        WHEN 'tracked' THEN 2
        WHEN 'correlated' THEN 3
        WHEN 'verified' THEN 4
        WHEN 'alerted' THEN 5
        ELSE 0
    END;
    new_rank := CASE NEW.state
        WHEN 'detected' THEN 1
        WHEN 'tracked' THEN 2
        WHEN 'correlated' THEN 3
        WHEN 'verified' THEN 4
        WHEN 'alerted' THEN 5
        ELSE 0
    END;
    IF old_rank > new_rank THEN
        NEW.state := OLD.state;
    END IF;
    NEW.created_token_count := GREATEST(OLD.created_token_count,NEW.created_token_count);
    NEW.dominant_holder_token_count := GREATEST(OLD.dominant_holder_token_count,NEW.dominant_holder_token_count);
    NEW.traded_token_count := GREATEST(OLD.traded_token_count,NEW.traded_token_count);
    NEW.related_actor_count := GREATEST(OLD.related_actor_count,NEW.related_actor_count);
    NEW.verified_evidence_count := GREATEST(OLD.verified_evidence_count,NEW.verified_evidence_count);
    NEW.observed_evidence_count := GREATEST(OLD.observed_evidence_count,NEW.observed_evidence_count);
    NEW.dossier := COALESCE(OLD.dossier,'{}'::jsonb) || COALESCE(NEW.dossier,'{}'::jsonb);
    NEW.first_seen_at := LEAST(OLD.first_seen_at,NEW.first_seen_at);
    NEW.last_seen_at := GREATEST(OLD.last_seen_at,NEW.last_seen_at);
    NEW.last_investigated_at := GREATEST(OLD.last_investigated_at,NEW.last_investigated_at);
    NEW.updated_at := now();
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS security_threat_tracks_preserve_history ON security_threat_tracks;
CREATE TRIGGER security_threat_tracks_preserve_history
BEFORE UPDATE ON security_threat_tracks
FOR EACH ROW
EXECUTE FUNCTION preserve_security_threat_track_history();

CREATE INDEX IF NOT EXISTS idx_security_threat_tracks_state_time
    ON security_threat_tracks (state,last_seen_at DESC);
CREATE INDEX IF NOT EXISTS idx_security_threat_tracks_target
    ON security_threat_tracks (network,target_kind,target_id);
CREATE INDEX IF NOT EXISTS idx_security_threat_tracks_last_investigated
    ON security_threat_tracks (last_investigated_at DESC);

-- The automatic correlation worker reads only a bounded 30-day raw sensor
-- window. These indexes keep that path independent from total historical table
-- growth while the actor evidence/index remains permanent.
CREATE INDEX IF NOT EXISTS idx_security_radar_events_creator_observation
    ON security_radar_events (
        network,
        (COALESCE(
            NULLIF(btrim(signals->>'creator_wallet'),''),
            NULLIF(btrim(signals->>'deployer_wallet'),'')
        )),
        target,
        created_at DESC
    )
    WHERE target_type='token'
      AND COALESCE(
            NULLIF(btrim(signals->>'creator_wallet'),''),
            NULLIF(btrim(signals->>'deployer_wallet'),'')
          ) IS NOT NULL;

CREATE INDEX IF NOT EXISTS idx_security_radar_holder_snapshots_latest_owner
    ON security_radar_holder_snapshots (
        network,target,owner_wallet,scanned_at DESC,id DESC
    )
    WHERE btrim(owner_wallet) <> '';
