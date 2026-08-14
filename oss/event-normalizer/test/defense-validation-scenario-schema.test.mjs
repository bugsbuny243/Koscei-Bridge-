import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import Ajv2020 from 'ajv/dist/2020.js';

const schemaURL = new URL('../../schemas/defense-validation-scenario-v0.1.schema.json', import.meta.url);
const scenarioURL = new URL('../../../docs/defense-validation/scenarios/solana-compromised-privileged-signer-v1.json', import.meta.url);
const schema = JSON.parse(await readFile(schemaURL, 'utf8'));
const canonicalScenario = JSON.parse(await readFile(scenarioURL, 'utf8'));
const ajv = new Ajv2020({ allErrors: true, strict: true });
const validate = ajv.compile(schema);

const cloneScenario = () => structuredClone(canonicalScenario);

test('defense scenario schema accepts the canonical planned attack and benign pair', () => {
  assert.equal(validate(canonicalScenario), true, JSON.stringify(validate.errors));
});

test('defense scenario schema cannot represent an executed result', () => {
  const scenario = cloneScenario();
  scenario.status = 'executed';
  scenario.claim_boundary.is_execution_evidence = true;
  scenario.verdict = 'validated';
  assert.equal(validate(scenario), false);
  assert.ok(validate.errors.some(error => error.instancePath === '/status' && error.keyword === 'const'));
  assert.ok(validate.errors.some(error => error.instancePath === '/claim_boundary/is_execution_evidence' && error.keyword === 'const'));
  assert.ok(validate.errors.some(error => error.instancePath === '' && error.keyword === 'additionalProperties'));
});

test('defense scenario schema requires exactly one attack and one benign control', () => {
  const scenario = cloneScenario();
  scenario.matrix.cases = scenario.matrix.cases.slice(0, 1);
  assert.equal(validate(scenario), false);
  assert.ok(validate.errors.some(error => error.instancePath === '/matrix/cases'));
});

test('defense scenario schema rejects mainnet and intent-label reversal', () => {
  const scenario = cloneScenario();
  scenario.claim_boundary.mainnet_transaction_sent = true;
  scenario.matrix.cases[0].authorization.approval_state = 'approved';
  scenario.matrix.cases[0].authorization.destination_policy = 'allowlisted';
  assert.equal(validate(scenario), false);
  assert.ok(validate.errors.some(error => error.instancePath === '/claim_boundary/mainnet_transaction_sent'));
  assert.ok(validate.errors.some(error => error.instancePath === '/matrix/cases/0/authorization/approval_state'));
  assert.ok(validate.errors.some(error => error.instancePath === '/matrix/cases/0/authorization/destination_policy'));
});
