-- Convergent Incident Corpus materialization.
--
-- Source arrival order must not matter:
--   * verified actor event first, signed material verdict later; or
--   * signed material verdict first, verified actor event later.
-- Both paths call the same target-scoped materializer.

CREATE OR REPLACE FUNCTION public.materialize_security_incident_for_target(
    p_network text,
    p_target text
)
RETURNS integer
LANGUAGE plpgsql
AS $$
DECLARE
    inserted_count integer := 0;
BEGIN
    IF btrim(COALESCE(p_network,'')) = '' OR btrim(COALESCE(p_target,'')) = '' THEN
        RETURN 0;
    END IF;

    WITH candidates AS (
        SELECT
            e.actor_wallet,
            e.network,
            e.target,
            e.event_kind,
            e.source_rule_id,
            e.signature AS event_signature,
            e.slot AS event_slot,
            e.observed_at AS event_observed_at,
            v.id AS verdict_id,
            v.signature AS verdict_signature,
            v.updated_at AS verdict_updated_at,
            v.rule_version AS verdict_rule_version,
            COALESCE(v.grade,'') AS grade,
            COALESCE(v.risk_index,0) AS risk_index,
            CASE
                WHEN lower(COALESCE(v.risk_level,''))='critical' OR COALESCE(v.risk_index,0)>=80 THEN 'critical'
                ELSE 'high'
            END AS risk_level,
            COALESCE(v.verdict,'') AS verdict,
            COALESCE(v.recommendation,'') AS recommendation,
            COALESCE(v.evidence,'[]'::jsonb) AS evidence,
            COALESCE(v.signals,'{}'::jsonb) AS signals,
            COALESCE(v.source,'') AS verdict_source
        FROM public.security_actor_exit_events e
        JOIN LATERAL (
            SELECT v.*
            FROM public.security_radar_verdicts v
            WHERE v.network=e.network
              AND v.target=e.target
              AND v.module_id='final_verdict_engine'
              AND v.signed=true
              AND v.signature IS NOT NULL
              AND btrim(v.signature)<>''
              AND btrim(COALESCE(v.rule_version,''))<>''
              AND (
                    lower(COALESCE(v.risk_level,'')) IN ('high','critical')
                    OR COALESCE(v.risk_index,0)>=60
                  )
              AND (
                    COALESCE(v.signals->>'verified_evidence','false')='true'
                    OR COALESCE(v.signals->>'real_onchain_evidence','false')='true'
                    OR COALESCE(v.signals->>'real_offchain_evidence','false')='true'
                  )
            ORDER BY v.updated_at DESC,v.risk_index DESC,v.id DESC
            LIMIT 1
        ) v ON true
        WHERE e.network=p_network
          AND e.target=p_target
          AND e.evidence_state='verified'
          AND btrim(e.actor_wallet)<>''
          AND btrim(e.signature)<>''
          AND e.slot>0
          AND e.observed_at<=now()+interval '5 minutes'
    ), prepared AS (
        SELECT
            c.*,
            'KIC1-' || encode(
                sha256(convert_to(
                    concat_ws(chr(31),
                        'koschei-incident-corpus-v1',
                        c.network,
                        c.target,
                        c.actor_wallet,
                        c.event_kind,
                        c.source_rule_id,
                        c.event_signature,
                        c.event_slot::text,
                        c.verdict_id::text,
                        c.verdict_signature,
                        ((extract(epoch FROM c.verdict_updated_at) * 1000000)::bigint)::text
                    ),
                    'UTF8'
                )),
                'hex'
            ) AS incident_key
        FROM candidates c
    ), hashed AS (
        SELECT
            p.*,
            'sha256:' || encode(
                sha256(convert_to(
                    concat_ws(chr(31),
                        p.incident_key,
                        p.verdict_rule_version,
                        p.grade,
                        p.risk_index::text,
                        p.risk_level,
                        p.verdict,
                        p.recommendation,
                        p.verdict_source,
                        p.evidence::text,
                        p.signals::text
                    ),
                    'UTF8'
                )),
                'hex'
            ) AS record_hash
        FROM prepared p
    ), versioned AS (
        SELECT h.*,
               previous.id AS supersedes_incident_id
        FROM hashed h
        LEFT JOIN LATERAL (
            SELECT c.id
            FROM public.security_incident_corpus c
            WHERE c.network=h.network
              AND c.target=h.target
              AND c.actor_wallet=h.actor_wallet
              AND c.event_kind=h.event_kind
              AND c.event_signature=h.event_signature
              AND c.incident_key<>h.incident_key
            ORDER BY c.verdict_updated_at DESC,c.created_at DESC,c.id DESC
            LIMIT 1
        ) previous ON true
    )
    INSERT INTO public.security_incident_corpus (
        incident_key,schema_version,network,target,actor_wallet,event_kind,source_rule_id,
        event_signature,event_slot,event_observed_at,verdict_id,verdict_signature,verdict_updated_at,
        verdict_rule_version,grade,risk_index,risk_level,verdict,recommendation,evidence,signals,
        verdict_source,record_hash,supersedes_incident_id,created_at
    )
    SELECT
        v.incident_key,'koschei-incident-corpus-v1',v.network,v.target,v.actor_wallet,v.event_kind,v.source_rule_id,
        v.event_signature,v.event_slot,v.event_observed_at,v.verdict_id,v.verdict_signature,v.verdict_updated_at,
        v.verdict_rule_version,v.grade,v.risk_index,v.risk_level,v.verdict,v.recommendation,v.evidence,v.signals,
        v.verdict_source,v.record_hash,v.supersedes_incident_id,now()
    FROM versioned v
    ON CONFLICT (incident_key) DO NOTHING;

    GET DIAGNOSTICS inserted_count = ROW_COUNT;
    RETURN inserted_count;
END;
$$;

CREATE OR REPLACE FUNCTION public.materialize_security_incident_from_exit_event()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.evidence_state='verified'
       AND btrim(COALESCE(NEW.signature,''))<>''
       AND COALESCE(NEW.slot,0)>0 THEN
        PERFORM public.materialize_security_incident_for_target(NEW.network,NEW.target);
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS security_incident_materialize_from_exit_event
    ON public.security_actor_exit_events;
CREATE TRIGGER security_incident_materialize_from_exit_event
AFTER INSERT OR UPDATE OF evidence_state,signature,slot,observed_at,source_rule_id
ON public.security_actor_exit_events
FOR EACH ROW EXECUTE FUNCTION public.materialize_security_incident_from_exit_event();

CREATE OR REPLACE FUNCTION public.materialize_security_incident_from_final_verdict()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.module_id='final_verdict_engine'
       AND NEW.signed=true
       AND btrim(COALESCE(NEW.signature,''))<>''
       AND (
            lower(COALESCE(NEW.risk_level,'')) IN ('high','critical')
            OR COALESCE(NEW.risk_index,0)>=60
           )
       AND (
            COALESCE(NEW.signals->>'verified_evidence','false')='true'
            OR COALESCE(NEW.signals->>'real_onchain_evidence','false')='true'
            OR COALESCE(NEW.signals->>'real_offchain_evidence','false')='true'
           ) THEN
        PERFORM public.materialize_security_incident_for_target(NEW.network,NEW.target);
    END IF;
    RETURN NEW;
END;
$$;

DROP TRIGGER IF EXISTS security_incident_materialize_from_final_verdict
    ON public.security_radar_verdicts;
CREATE TRIGGER security_incident_materialize_from_final_verdict
AFTER INSERT OR UPDATE OF signed,signature,risk_index,risk_level,verdict,recommendation,evidence,signals,rule_version,updated_at
ON public.security_radar_verdicts
FOR EACH ROW EXECUTE FUNCTION public.materialize_security_incident_from_final_verdict();

-- Backfill existing strict evidence conjunctions once. The function is
-- idempotent, so re-running the migration on a fresh database remains safe.
DO $$
DECLARE
    item record;
BEGIN
    FOR item IN
        SELECT DISTINCT network,target
        FROM public.security_actor_exit_events
        WHERE evidence_state='verified'
          AND btrim(signature)<>''
          AND slot>0
    LOOP
        PERFORM public.materialize_security_incident_for_target(item.network,item.target);
    END LOOP;
END;
$$;
