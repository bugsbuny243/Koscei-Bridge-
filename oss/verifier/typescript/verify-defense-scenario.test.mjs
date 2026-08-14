import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import test from 'node:test';

import {
  DEFENSE_SCENARIO_CONTRACT,
  DEFENSE_VALIDATION_RULESET,
  verifyDefenseScenarioObject
} from './verify-defense-scenario.mjs';

const scenarioURL = new URL('../../../docs/defense-validation/scenarios/solana-compromised-privileged-signer-v1.json', import.meta.url);
const schemaURL = new URL('../../schemas/defense-validation-scenario-v0.1.schema.json', import.meta.url);
const canonicalScenario = JSON.parse(await readFile(scenarioURL, 'utf8'));

const cloneScenario = () => structuredClone(canonicalScenario);

function expectError(result, wanted) {
  assert.equal(result.ok, false, JSON.stringify(result));
  assert.ok(result.errors.some(error => error.includes(wanted)), `${wanted} not found in ${JSON.stringify(result.errors)}`);
}

test('canonical planned Solana attack and benign pair is accepted without a result claim', () => {
  const result = verifyDefenseScenarioObject(canonicalScenario);
  assert.deepEqual(result, {
    ok: true,
    errors: [],
    scenario_ref: 'scenario:solana:compromised-privileged-signer',
    scenario_version: 'v1.0.0',
    status: 'planned'
  });
  assert.equal(canonicalScenario.contract, DEFENSE_SCENARIO_CONTRACT);
  assert.equal(canonicalScenario.ruleset_version, DEFENSE_VALIDATION_RULESET);
  assert.equal(canonicalScenario.claim_boundary.is_execution_evidence, false);
  assert.equal(canonicalScenario.claim_boundary.is_validation_result, false);
});

test('scenario definition cannot be promoted to an executed validation result', () => {
  const scenario = cloneScenario();
  scenario.status = 'executed';
  scenario.claim_boundary.is_execution_evidence = true;
  scenario.claim_boundary.is_validation_result = true;
  scenario.verdict = 'validated';
  scenario.run_ref = 'KDVR1-fabricated';
  const result = verifyDefenseScenarioObject(scenario);
  expectError(result, 'manifest.status:must_equal:planned');
  expectError(result, 'claim_boundary.is_execution_evidence:must_equal:false');
  expectError(result, 'runtime_evidence_forbidden:manifest.verdict');
  expectError(result, 'runtime_evidence_forbidden:manifest.run_ref');
});

test('scenario definition rejects run hashes even when nested inside a case', () => {
  const scenario = cloneScenario();
  scenario.matrix.cases[0].execution_hash = `sha256:${'a'.repeat(64)}`;
  const result = verifyDefenseScenarioObject(scenario);
  expectError(result, 'runtime_evidence_forbidden:manifest.matrix.cases[0].execution_hash');
  expectError(result, 'matrix.cases[0]:unexpected:execution_hash');
});

test('matrix requires one attack and one matched benign control', () => {
  const missingBenign = cloneScenario();
  missingBenign.matrix.cases = missingBenign.matrix.cases.slice(0, 1);
  expectError(verifyDefenseScenarioObject(missingBenign), 'matrix.cases:must_contain_exactly_two');

  const mismatchedSurface = cloneScenario();
  mismatchedSurface.matrix.cases[1].stimulus.amount_atomic = '2000000000';
  expectError(
    verifyDefenseScenarioObject(mismatchedSurface),
    'matrix.cases:matched_field_mismatch:stimulus.amount_atomic'
  );
});

test('mainnet, network, signature bypass and arbitrary state writes fail closed', () => {
  const scenario = cloneScenario();
  scenario.claim_boundary.mainnet_transaction_sent = true;
  scenario.environment.network_access = true;
  scenario.environment.mainnet_rpc_allowed = true;
  scenario.environment.signature_verification_disabled = true;
  scenario.environment.arbitrary_account_writes_allowed = true;
  const result = verifyDefenseScenarioObject(scenario);
  expectError(result, 'claim_boundary.mainnet_transaction_sent:must_equal:false');
  expectError(result, 'environment.network_access:must_equal:false');
  expectError(result, 'environment.mainnet_rpc_allowed:must_equal:false');
  expectError(result, 'environment.signature_verification_disabled:must_equal:false');
  expectError(result, 'environment.arbitrary_account_writes_allowed:must_equal:false');
});

test('key material fields and production identities are prohibited', () => {
  const scenario = cloneScenario();
  scenario.matrix.cases[0].authorization.production_identity_used = true;
  scenario.matrix.cases[0].authorization.secret_key = 'not-real-but-still-forbidden';
  const result = verifyDefenseScenarioObject(scenario);
  expectError(result, 'key_material_forbidden:manifest.matrix.cases[0].authorization.secret_key');
  expectError(result, 'matrix.cases[0].authorization.production_identity_used:must_equal:false');
});

test('taxonomy requires an exact MITRE AADAPT technique identifier and URL', () => {
  const scenario = cloneScenario();
  scenario.taxonomy.primary_technique_id = 'AADAPT:privileged-access';
  scenario.taxonomy.primary_technique_url = 'https://aadapt.mitre.org/techniques/privileged-access/';
  const result = verifyDefenseScenarioObject(scenario);
  expectError(result, 'taxonomy.primary_technique_id:invalid_aadapt_id');
  expectError(result, 'taxonomy.primary_technique_url:must_equal:');
});

test('attack must alert by impact while benign control must remain silent', () => {
  const lateExpectation = cloneScenario();
  lateExpectation.matrix.cases[0].expected_control_behavior.latest_alert_offset_ms = 1200;
  expectError(
    verifyDefenseScenarioObject(lateExpectation),
    'latest_alert_offset_ms:must_equal_impact_deadline'
  );

  const benignAlert = cloneScenario();
  benignAlert.matrix.cases[1].expected_control_behavior.alert_required = true;
  benignAlert.matrix.cases[1].expected_control_behavior.expected_signal = 'unauthorized_privileged_withdrawal';
  benignAlert.matrix.cases[1].expected_control_behavior.latest_alert_offset_ms = 1000;
  expectError(
    verifyDefenseScenarioObject(benignAlert),
    'matrix.cases[1].expected_control_behavior.alert_required:must_equal:false'
  );
});

test('required future evidence checklist is exact and cannot be weakened', () => {
  const scenario = cloneScenario();
  scenario.required_run_evidence = scenario.required_run_evidence.filter(item => item !== 'independent_observation_hash');
  expectError(verifyDefenseScenarioObject(scenario), 'required_run_evidence:set_mismatch');
});

test('methodology, taxonomy and execution-engine provenance are all required', () => {
  const scenario = cloneScenario();
  scenario.references[2] = structuredClone(scenario.references[1]);
  const result = verifyDefenseScenarioObject(scenario);
  expectError(result, 'references:duplicate_role:methodology');
  expectError(result, 'references:missing_role:execution-engine');
});

test('JSON Schema is strict and represents planned definitions rather than run records', async () => {
  const schema = JSON.parse(await readFile(schemaURL, 'utf8'));
  assert.equal(schema.$schema, 'https://json-schema.org/draft/2020-12/schema');
  assert.equal(schema.additionalProperties, false);
  assert.equal(schema.properties.contract.const, DEFENSE_SCENARIO_CONTRACT);
  assert.equal(schema.properties.status.const, 'planned');
  assert.equal(schema.$defs.claimBoundary.properties.is_execution_evidence.const, false);
  assert.equal(schema.$defs.claimBoundary.properties.is_validation_result.const, false);
  assert.equal(Object.hasOwn(schema.properties, 'run_ref'), false);
  assert.equal(Object.hasOwn(schema.properties, 'verdict'), false);
  assert.equal(Object.hasOwn(schema.properties, 'report_hash'), false);

  const refs = [];
  const visit = value => {
    if (Array.isArray(value)) return value.forEach(visit);
    if (!value || typeof value !== 'object') return;
    if (typeof value.$ref === 'string') refs.push(value.$ref);
    Object.values(value).forEach(visit);
  };
  visit(schema);
  for (const ref of refs) {
    assert.match(ref, /^#\/\$defs\/[A-Za-z]+$/);
    assert.ok(schema.$defs[ref.split('/').at(-1)], `unresolved schema ref: ${ref}`);
  }
});
