'use strict';

const fs = require('node:fs');

const REGISTRY_SCHEMA = 'koschei-public-case-registry-v1';
const CASE_REF_PATTERN = /^KD1-[a-z2-7]{32}$/;
const BUNDLE_HASH_PATTERN = /^sha256:[0-9a-f]{64}$/;
const ALLOWED_TIME_STATES = new Set(['db_verified', 'legacy_event', 'legacy_column']);
const ALLOWED_LEDGER_STATES = new Set(['verified', 'legacy_unlinked']);
const ALLOWED_PUBLISHERS = new Set(['owner', 'koschei-autopublish/v1']);
const ALLOWED_PUBLICATION_ACTIONS = new Set(['publish', 'hide', 'feature', 'unfeature', 'update', 'draft']);

function fail(message) {
  throw new Error(`public registry smoke contract: ${message}`);
}

function integerField(payload, name) {
  const value = payload[name];
  if (!Number.isSafeInteger(value) || value < 0) fail(`${name} must be a non-negative safe integer`);
  return value;
}

function validTimestamp(value) {
  if (value === undefined || value === null || String(value).trim() === '') return false;
  return !Number.isNaN(new Date(value).getTime());
}

function validatePublicRegistrySmoke(payload) {
  if (!payload || typeof payload !== 'object' || Array.isArray(payload)) fail('response must be an object');
  if (payload.ok !== true) fail('ok must be true');
  if (payload.schema_version !== REGISTRY_SCHEMA) fail(`schema_version must be ${REGISTRY_SCHEMA}`);
  if (!validTimestamp(payload.generated_at)) fail('generated_at must be a valid timestamp');
  if (!Array.isArray(payload.cases)) fail('cases must be an array');

  const total = integerField(payload, 'total_publications');
  const inspected = integerField(payload, 'inspected_publications');
  const invalid = integerField(payload, 'invalid_publications');
  const uninspected = integerField(payload, 'uninspected_publications');
  const ledgerVerified = integerField(payload, 'ledger_verified_publications');
  const legacyUnlinked = integerField(payload, 'legacy_unlinked_publications');
  const invalidLedger = integerField(payload, 'invalid_ledger_publications');
  const count = integerField(payload, 'count');

  if (inspected !== count + invalid) fail('inspected_publications must equal count + invalid_publications');
  if (total !== inspected + uninspected) fail('total_publications must equal inspected + uninspected');
  if (ledgerVerified + legacyUnlinked + invalidLedger !== inspected) fail('publication ledger counts must equal inspected_publications');
  if (payload.cases.length !== count) fail('cases length must equal count');

  const expectedComplete = invalid === 0 && uninspected === 0;
  const expectedStatus = invalid > 0 ? 'degraded' : uninspected > 0 ? 'partial' : 'operational';
  if (payload.registry_complete !== expectedComplete || payload.registry_status !== expectedStatus) {
    fail('registry status/completeness is inconsistent with publication counts');
  }
  const expectedLedgerComplete = invalidLedger === 0 && uninspected === 0 && legacyUnlinked === 0;
  const expectedLedgerStatus = invalidLedger > 0 ? 'degraded' : uninspected > 0 ? 'partial' : legacyUnlinked > 0 ? 'legacy_mixed' : 'verified';
  if (payload.publication_ledger_complete !== expectedLedgerComplete || payload.publication_ledger_status !== expectedLedgerStatus) {
    fail('publication ledger status/completeness is inconsistent with ledger counts');
  }

  if (invalid !== 0 || invalidLedger !== 0) {
    fail('production registry cannot contain invalid inspected publications or invalid ledger records');
  }
  if (ledgerVerified + legacyUnlinked !== inspected || count !== inspected) {
    fail('all inspected publications must be returned with declared ledger lineage');
  }

  const policy = payload.publication_policy;
  if (!policy || typeof policy !== 'object' || Array.isArray(policy)) fail('publication_policy must be an object');
  for (const key of [
    'canonical_bundle_hash_reverified',
    'publication_ledger_readback_verified',
    'publication_effective_time_event_backed',
    'db_owned_publication_time_v1',
  ]) {
    if (policy[key] !== true) fail(`publication_policy.${key} must be true`);
  }
  if (policy.transition_identifiers_public !== false) fail('transition identifiers must remain non-public');

  if (total === 0) {
    if (payload.registry_status !== 'operational' || payload.registry_complete !== true) {
      fail('empty registry must be operational and complete');
    }
    if (payload.publication_ledger_status !== 'verified' || payload.publication_ledger_complete !== true) {
      fail('empty registry publication ledger must be verified and complete');
    }
    return { mode: 'empty_healthy', case_ref: null, registry_complete: true, legacy_lineage: false };
  }

  for (const item of payload.cases) {
    if (!item || typeof item !== 'object' || Array.isArray(item)) fail('case entry must be an object');
    if (!CASE_REF_PATTERN.test(String(item.case_ref || ''))) fail('case_ref is invalid');
    if (!BUNDLE_HASH_PATTERN.test(String(item.bundle_hash || ''))) fail(`bundle_hash is invalid for ${item.case_ref}`);
    if (!ALLOWED_LEDGER_STATES.has(String(item.publication_ledger_status || ''))) fail(`publication ledger state is invalid for ${item.case_ref}`);
    if (!ALLOWED_PUBLISHERS.has(String(item.published_by || ''))) fail(`publisher identity is invalid for ${item.case_ref}`);
    if (item.publication_ledger_status === 'verified') {
      if (!ALLOWED_PUBLICATION_ACTIONS.has(String(item.publication_action || ''))) fail(`publication action is invalid for ${item.case_ref}`);
    } else if (String(item.publication_action || '').trim() !== '') {
      fail(`legacy publication lineage must not invent an action for ${item.case_ref}`);
    }
    if (!ALLOWED_TIME_STATES.has(String(item.publication_time_status || ''))) fail(`publication time provenance is invalid for ${item.case_ref}`);
    if (!validTimestamp(item.published_at)) fail(`published_at is invalid for ${item.case_ref}`);
    if (Object.prototype.hasOwnProperty.call(item, 'transition_id')) fail('transition_id must not be public');
  }

  return {
    mode: 'case',
    case_ref: payload.cases[0].case_ref,
    registry_complete: payload.registry_complete === true,
    legacy_lineage: legacyUnlinked > 0,
  };
}

const sleep = ms => new Promise(resolve => setTimeout(resolve, ms));

function validateResponseText(text) {
  return validatePublicRegistrySmoke(JSON.parse(text));
}

async function runCLI() {
  const file = process.argv[2];
  if (!file) fail('response file path is required');

  let responseText = fs.readFileSync(file, 'utf8');
  const retryDeployment = process.env.GITHUB_EVENT_NAME !== 'pull_request' && Boolean(process.env.BASE_URL);
  const attempts = retryDeployment ? 12 : 1;
  let lastError;

  for (let attempt = 1; attempt <= attempts; attempt += 1) {
    try {
      const result = validateResponseText(responseText);
      process.stdout.write(`${JSON.stringify(result)}\n`);
      return;
    } catch (error) {
      lastError = error;
      if (attempt === attempts) break;
      console.error(`PUBLIC_REGISTRY_WAITING_FOR_SEMANTIC_DEPLOY: attempt=${attempt}/${attempts} ${error.message}`);
      await sleep(10000);
      const response = await fetch(`${process.env.BASE_URL}/api/public/cases?limit=100`, {
        cache: 'no-store',
        headers: { Accept: 'application/json' },
      });
      if (response.ok) responseText = await response.text();
    }
  }
  throw lastError;
}

if (require.main === module) {
  runCLI().catch(error => {
    console.error(error instanceof Error ? error.message : String(error));
    process.exit(2);
  });
}

module.exports = { validatePublicRegistrySmoke };
