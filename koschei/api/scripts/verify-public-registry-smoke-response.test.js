'use strict';

const assert = require('node:assert/strict');
const { validatePublicRegistrySmoke } = require('./verify-public-registry-smoke-response.js');

function basePayload() {
  return {
    ok: true,
    schema_version: 'koschei-public-case-registry-v1',
    generated_at: '2026-08-12T10:00:00Z',
    registry_status: 'operational',
    registry_complete: true,
    publication_ledger_status: 'verified',
    publication_ledger_complete: true,
    total_publications: 0,
    inspected_publications: 0,
    invalid_publications: 0,
    uninspected_publications: 0,
    ledger_verified_publications: 0,
    legacy_unlinked_publications: 0,
    invalid_ledger_publications: 0,
    count: 0,
    publication_policy: {
      canonical_bundle_hash_reverified: true,
      publication_ledger_readback_verified: true,
      publication_effective_time_event_backed: true,
      db_owned_publication_time_v1: true,
      transition_identifiers_public: false,
    },
    cases: [],
  };
}

function verifiedCase() {
  return {
    case_ref: 'KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    bundle_hash: `sha256:${'1'.repeat(64)}`,
    publication_ledger_status: 'verified',
    published_by: 'koschei-autopublish/v1',
    publication_action: 'publish',
    publication_time_status: 'db_verified',
    published_at: '2026-08-12T09:59:00Z',
  };
}

{
  const result = validatePublicRegistrySmoke(basePayload());
  assert.deepEqual(result, { mode: 'empty_healthy', case_ref: null, registry_complete: true, legacy_lineage: false });
}

{
  const payload = basePayload();
  delete payload.generated_at;
  assert.throws(() => validatePublicRegistrySmoke(payload), /generated_at must be a valid timestamp/);
}

{
  const payload = basePayload();
  payload.registry_status = 'degraded';
  assert.throws(() => validatePublicRegistrySmoke(payload), /registry status\/completeness is inconsistent/);
}

{
  const payload = basePayload();
  payload.total_publications = 1;
  assert.throws(() => validatePublicRegistrySmoke(payload), /total_publications must equal inspected \+ uninspected/);
}

{
  const payload = basePayload();
  payload.total_publications = 1;
  payload.inspected_publications = 1;
  payload.ledger_verified_publications = 1;
  payload.count = 1;
  payload.cases = [verifiedCase()];
  const result = validatePublicRegistrySmoke(payload);
  assert.deepEqual(result, {
    mode: 'case',
    case_ref: 'KD1-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa',
    registry_complete: true,
    legacy_lineage: false,
  });
}

{
  const payload = basePayload();
  payload.total_publications = 1;
  payload.inspected_publications = 1;
  payload.legacy_unlinked_publications = 1;
  payload.publication_ledger_status = 'legacy_mixed';
  payload.publication_ledger_complete = false;
  payload.count = 1;
  payload.cases = [{
    ...verifiedCase(),
    publication_ledger_status: 'legacy_unlinked',
    publication_action: '',
    published_by: 'owner',
    publication_time_status: 'legacy_column',
  }];
  const result = validatePublicRegistrySmoke(payload);
  assert.equal(result.mode, 'case');
  assert.equal(result.legacy_lineage, true);
}

{
  const payload = basePayload();
  payload.total_publications = 1;
  payload.inspected_publications = 1;
  payload.legacy_unlinked_publications = 1;
  payload.publication_ledger_status = 'legacy_mixed';
  payload.publication_ledger_complete = false;
  payload.count = 1;
  payload.cases = [{
    ...verifiedCase(),
    publication_ledger_status: 'legacy_unlinked',
    publication_action: 'publish',
    published_by: 'owner',
  }];
  assert.throws(() => validatePublicRegistrySmoke(payload), /must not invent an action/);
}

{
  const payload = basePayload();
  payload.total_publications = 101;
  payload.inspected_publications = 100;
  payload.uninspected_publications = 1;
  payload.ledger_verified_publications = 100;
  payload.count = 100;
  payload.registry_status = 'partial';
  payload.registry_complete = false;
  payload.publication_ledger_status = 'partial';
  payload.publication_ledger_complete = false;
  payload.cases = Array.from({ length: 100 }, (_, index) => ({
    ...verifiedCase(),
    case_ref: `KD1-${index.toString(2).padStart(32, 'a').replace(/0/g, 'a').replace(/1/g, 'b')}`,
    bundle_hash: `sha256:${String(index % 10).repeat(64)}`,
  }));
  const result = validatePublicRegistrySmoke(payload);
  assert.equal(result.mode, 'case');
  assert.equal(result.registry_complete, false);
}

{
  const payload = basePayload();
  payload.total_publications = 1;
  payload.inspected_publications = 1;
  payload.ledger_verified_publications = 1;
  payload.count = 1;
  payload.cases = [{ ...verifiedCase(), published_by: 'unknown' }];
  assert.throws(() => validatePublicRegistrySmoke(payload), /publisher identity is invalid/);
}

{
  const payload = basePayload();
  payload.total_publications = 1;
  payload.inspected_publications = 1;
  payload.ledger_verified_publications = 1;
  payload.count = 1;
  payload.cases = [{ ...verifiedCase(), publication_action: '' }];
  assert.throws(() => validatePublicRegistrySmoke(payload), /publication action is invalid/);
}

{
  const payload = basePayload();
  payload.total_publications = 1;
  payload.inspected_publications = 1;
  payload.ledger_verified_publications = 1;
  payload.count = 1;
  payload.cases = [{ ...verifiedCase(), published_at: 'not-a-time' }];
  assert.throws(() => validatePublicRegistrySmoke(payload), /published_at is invalid/);
}

{
  const payload = basePayload();
  payload.total_publications = 1;
  payload.inspected_publications = 1;
  payload.ledger_verified_publications = 1;
  payload.count = 1;
  payload.cases = [{ ...verifiedCase(), transition_id: 'must-not-leak' }];
  assert.throws(() => validatePublicRegistrySmoke(payload), /transition_id must not be public/);
}

console.log('public registry smoke response tests: ok');
