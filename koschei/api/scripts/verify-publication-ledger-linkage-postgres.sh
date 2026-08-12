#!/usr/bin/env bash
set -euo pipefail

: "${KOSCHEI_TEST_DATABASE_URL:?KOSCHEI_TEST_DATABASE_URL is required}"
PSQL=(psql "${KOSCHEI_TEST_DATABASE_URL}" --set=ON_ERROR_STOP=1 --no-psqlrc)
HASH='sha256:44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a'
OWNER_CASE='KD1-cccccccccccccccccccccccccccccccc'
AUTO_CASE='KD1-dddddddddddddddddddddddddddddddd'
HIDDEN_CASE='KD1-eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'

"${PSQL[@]}" <<SQL
INSERT INTO dossier_source_snapshots
    (mint,network,verdict_signature,ruleset_version,produced_at,source_hash,canonical_source,source_payload)
VALUES
    ('ledger-mint','solana-mainnet','ledger-linkage-signature','ledger-v1',now(),'${HASH}',convert_to('{}','UTF8'),'{}'::jsonb)
ON CONFLICT (verdict_signature) DO NOTHING;

INSERT INTO dossier_exports
    (case_ref,mint,verdict_signature,source_snapshot_id,bundle_hash,canonical_bundle,bundle_json,requested_by)
SELECT '${OWNER_CASE}','ledger-mint','ledger-linkage-signature',id,'${HASH}',convert_to('{}','UTF8'),'{}'::jsonb,'ledger-test'
FROM dossier_source_snapshots WHERE verdict_signature='ledger-linkage-signature'
ON CONFLICT (case_ref) DO NOTHING;

INSERT INTO dossier_exports
    (case_ref,mint,verdict_signature,source_snapshot_id,bundle_hash,canonical_bundle,bundle_json,requested_by)
SELECT '${AUTO_CASE}','ledger-mint','ledger-linkage-signature',id,'${HASH}',convert_to('{}','UTF8'),'{}'::jsonb,'ledger-test'
FROM dossier_source_snapshots WHERE verdict_signature='ledger-linkage-signature'
ON CONFLICT (case_ref) DO NOTHING;

INSERT INTO dossier_exports
    (case_ref,mint,verdict_signature,source_snapshot_id,bundle_hash,canonical_bundle,bundle_json,requested_by)
SELECT '${HIDDEN_CASE}','ledger-mint','ledger-linkage-signature',id,'${HASH}',convert_to('{}','UTF8'),'{}'::jsonb,'ledger-test'
FROM dossier_source_snapshots WHERE verdict_signature='ledger-linkage-signature'
ON CONFLICT (case_ref) DO NOTHING;
SQL

# A normal owner publication and its app-written event must commit. The database
# supplies the transition ID and canonical state fields to the event.
"${PSQL[@]}" <<SQL
BEGIN;
INSERT INTO dossier_publications
    (case_ref,status,public_title,public_summary,featured,redaction_profile,published_at,published_by,created_at,updated_at)
VALUES
    ('${OWNER_CASE}','public','Ledger Case','linked owner transition',false,'public-onchain-v1',now(),'owner',now(),now());
INSERT INTO dossier_publication_events (case_ref,action,actor,publication_state)
VALUES ('${OWNER_CASE}','publish','owner','{}'::jsonb);
COMMIT;

DO \$\$
DECLARE
    publication_transition uuid;
    event_transition uuid;
    state jsonb;
BEGIN
    SELECT transition_id INTO publication_transition
    FROM dossier_publications WHERE case_ref='${OWNER_CASE}';
    SELECT transition_id, publication_state INTO event_transition, state
    FROM dossier_publication_events WHERE case_ref='${OWNER_CASE}' AND action='publish';
    IF publication_transition IS NULL OR event_transition IS DISTINCT FROM publication_transition THEN
        RAISE EXCEPTION 'owner transition id was not linked to immutable event';
    END IF;
    IF state->>'status' <> 'public'
       OR state->>'published_by' <> 'owner'
       OR state->>'public_title' <> 'Ledger Case'
       OR state->>'public_summary' <> 'linked owner transition'
       OR state->>'redaction_profile' <> 'public-onchain-v1'
       OR state->>'featured' <> 'false' THEN
        RAISE EXCEPTION 'owner event snapshot was not canonicalized from publication state: %', state;
    END IF;
END
\$\$;
SQL

# A direct state mutation without a matching event must fail at commit time.
if "${PSQL[@]}" >/tmp/koschei-ledger-orphan.log 2>&1 <<SQL
BEGIN;
UPDATE dossier_publications
SET public_title='orphaned mutation', updated_at=now()
WHERE case_ref='${OWNER_CASE}';
COMMIT;
SQL
then
    echo 'publication ledger linkage failure: orphaned publication mutation committed' >&2
    cat /tmp/koschei-ledger-orphan.log >&2
    exit 1
fi
grep -q 'missing its matching immutable transition event' /tmp/koschei-ledger-orphan.log

# A second valid transition must receive a fresh ID and a second immutable event.
"${PSQL[@]}" <<SQL
BEGIN;
UPDATE dossier_publications
SET public_title='Ledger Case v2', updated_at=now()
WHERE case_ref='${OWNER_CASE}';
INSERT INTO dossier_publication_events (case_ref,action,actor,publication_state)
VALUES ('${OWNER_CASE}','update','owner','{}'::jsonb);
COMMIT;

DO \$\$
DECLARE
    event_count integer;
    transition_count integer;
    current_transition uuid;
    current_event_transition uuid;
BEGIN
    SELECT count(*), count(DISTINCT transition_id)
    INTO event_count, transition_count
    FROM dossier_publication_events WHERE case_ref='${OWNER_CASE}';
    IF event_count <> 2 OR transition_count <> 2 THEN
        RAISE EXCEPTION 'publication transitions did not receive unique immutable event ids: events %, ids %', event_count, transition_count;
    END IF;
    SELECT transition_id INTO current_transition FROM dossier_publications WHERE case_ref='${OWNER_CASE}';
    SELECT transition_id INTO current_event_transition
    FROM dossier_publication_events
    WHERE case_ref='${OWNER_CASE}' AND publication_state->>'public_title'='Ledger Case v2';
    IF current_event_transition IS DISTINCT FROM current_transition THEN
        RAISE EXCEPTION 'current publication transition does not point at latest immutable event';
    END IF;
END
\$\$;
SQL

# The immutable event actor must match the current publication publisher.
if "${PSQL[@]}" >/tmp/koschei-ledger-actor.log 2>&1 <<SQL
BEGIN;
UPDATE dossier_publications
SET public_summary='wrong actor transition', updated_at=now()
WHERE case_ref='${OWNER_CASE}';
INSERT INTO dossier_publication_events (case_ref,action,actor,publication_state)
VALUES ('${OWNER_CASE}','update','autopublish','{}'::jsonb);
COMMIT;
SQL
then
    echo 'publication ledger linkage failure: mismatched actor committed' >&2
    cat /tmp/koschei-ledger-actor.log >&2
    exit 1
fi
grep -q 'event actor does not match publisher' /tmp/koschei-ledger-actor.log

# Autopublish uses its distinct publisher/actor identity and must link cleanly.
"${PSQL[@]}" <<SQL
BEGIN;
INSERT INTO dossier_publications
    (case_ref,status,public_title,public_summary,featured,redaction_profile,published_at,published_by,created_at,updated_at)
VALUES
    ('${AUTO_CASE}','public','Autopublish Case','linked autopublish transition',false,'public-onchain-v1',now(),'koschei-autopublish/v1',now(),now());
INSERT INTO dossier_publication_events (case_ref,action,actor,publication_state)
VALUES ('${AUTO_CASE}','publish','autopublish','{}'::jsonb);
COMMIT;

DO \$\$
DECLARE linked boolean;
BEGIN
    SELECT EXISTS (
        SELECT 1
        FROM dossier_publications p
        JOIN dossier_publication_events e ON e.transition_id=p.transition_id AND e.case_ref=p.case_ref
        WHERE p.case_ref='${AUTO_CASE}'
          AND p.published_by='koschei-autopublish/v1'
          AND e.actor='autopublish'
          AND e.action='publish'
          AND e.publication_state->>'published_by'='koschei-autopublish/v1'
    ) INTO linked;
    IF NOT linked THEN RAISE EXCEPTION 'autopublish transition was not linked'; END IF;
END
\$\$;
SQL

# Existing owner code can call the first hidden state "hidden". The database
# normalizes that request to the durable action vocabulary "hide" before checks.
"${PSQL[@]}" <<SQL
BEGIN;
INSERT INTO dossier_publications
    (case_ref,status,public_title,public_summary,featured,redaction_profile,published_at,published_by,created_at,updated_at)
VALUES
    ('${HIDDEN_CASE}','hidden','','',false,'public-onchain-v1',NULL,'owner',now(),now());
INSERT INTO dossier_publication_events (case_ref,action,actor,publication_state)
VALUES ('${HIDDEN_CASE}','hidden','owner','{}'::jsonb);
COMMIT;

DO \$\$
DECLARE action_value text;
BEGIN
    SELECT action INTO action_value FROM dossier_publication_events WHERE case_ref='${HIDDEN_CASE}';
    IF action_value <> 'hide' THEN
        RAISE EXCEPTION 'first hidden transition was not normalized to hide: %', action_value;
    END IF;
END
\$\$;
SQL

echo 'publication ledger linkage postgres acceptance: ok'
