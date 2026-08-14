#!/usr/bin/env node

import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

export const DEFENSE_SCENARIO_CONTRACT = 'koschei-defense-validation-scenario-v0.1';
export const DEFENSE_VALIDATION_RULESET = 'koschei-defense-validation-rules-v0.1.0';

const SHA256_RUNTIME_FIELDS = new Set([
  'execution_hash',
  'pre_state_hash',
  'post_state_hash',
  'observation_evidence_hash',
  'alert_evidence_hash',
  'report_hash'
]);

const RUNTIME_RESULT_FIELDS = new Set([
  'run_ref',
  'execution_ref',
  'evidence_state',
  'observation_evidence_ref',
  'alert_evidence_ref',
  'observation_completed_offset_ms',
  'alert_observed_offset_ms',
  'outcome',
  'detection_ms',
  'lead_time_ms',
  'verdict',
  'validated_at',
  'executed_at'
]);

const KEY_MATERIAL_FIELDS = new Set([
  'private_key',
  'secret_key',
  'seed_phrase',
  'mnemonic',
  'signing_material',
  'wallet_seed'
]);

const MATCHED_FIELDS = [
  'stimulus.program_fixture',
  'stimulus.instruction',
  'stimulus.asset',
  'stimulus.amount_atomic',
  'observation_window_ms'
];

const PLANNED_OPERATIONS = [
  'prepare_ephemeral_fixture_state',
  'present_withdrawal_to_control',
  'execute_owner_approved_isolated_fixture',
  'complete_independent_observation_window'
];

const REQUIRED_RUN_EVIDENCE = [
  'execution_hash',
  'pre_state_hash',
  'post_state_hash',
  'independent_observation_hash',
  'alert_hash_if_alerted',
  'control_configuration_hash',
  'completed_observation_window',
  'execution_engine_attestation'
];

const TOP_LEVEL_KEYS = [
  '$schema',
  'contract',
  'scenario_ref',
  'scenario_version',
  'title',
  'status',
  'chain',
  'ruleset_version',
  'taxonomy',
  'claim_boundary',
  'environment',
  'safety_gates',
  'control_contract',
  'matrix',
  'required_run_evidence',
  'limitations',
  'references'
];

function isObject(value) {
  return Boolean(value) && typeof value === 'object' && !Array.isArray(value);
}

function exactKeys(value, path, expected, errors) {
  if (!isObject(value)) {
    errors.push(`${path}:must_be_object`);
    return false;
  }
  const actual = Object.keys(value);
  for (const key of expected) {
    if (!Object.hasOwn(value, key)) errors.push(`${path}:missing:${key}`);
  }
  for (const key of actual) {
    if (!expected.includes(key)) errors.push(`${path}:unexpected:${key}`);
  }
  return true;
}

function exactSet(value, path, expected, errors) {
  if (!Array.isArray(value)) {
    errors.push(`${path}:must_be_array`);
    return false;
  }
  const actual = value.map(item => String(item));
  if (new Set(actual).size !== actual.length) errors.push(`${path}:duplicates`);
  if (actual.length !== expected.length || expected.some(item => !actual.includes(item))) {
    errors.push(`${path}:set_mismatch`);
    return false;
  }
  return true;
}

function nonEmptyString(value, path, errors, minimumLength = 1) {
  if (typeof value !== 'string' || value.trim().length < minimumLength) {
    errors.push(`${path}:invalid_string`);
    return false;
  }
  return true;
}

function requireValue(actual, expected, path, errors) {
  if (actual !== expected) errors.push(`${path}:must_equal:${String(expected)}`);
}

function walkForbiddenFields(value, path, errors) {
  if (Array.isArray(value)) {
    value.forEach((item, index) => walkForbiddenFields(item, `${path}[${index}]`, errors));
    return;
  }
  if (!isObject(value)) return;
  for (const [key, item] of Object.entries(value)) {
    const itemPath = `${path}.${key}`;
    if (SHA256_RUNTIME_FIELDS.has(key) || RUNTIME_RESULT_FIELDS.has(key)) {
      errors.push(`runtime_evidence_forbidden:${itemPath}`);
    }
    if (KEY_MATERIAL_FIELDS.has(key)) errors.push(`key_material_forbidden:${itemPath}`);
    walkForbiddenFields(item, itemPath, errors);
  }
}

function verifyTaxonomy(taxonomy, errors) {
  const path = 'taxonomy';
  if (!exactKeys(taxonomy, path, [
    'framework',
    'primary_technique_id',
    'primary_technique_url',
    'mapping_rationale',
    'secondary_technique_ids'
  ], errors)) return;
  requireValue(taxonomy.framework, 'MITRE AADAPT', `${path}.framework`, errors);
  const techniquePattern = /^ADT\d{4}(?:\.\d{3})?$/;
  if (!techniquePattern.test(String(taxonomy.primary_technique_id ?? ''))) {
    errors.push(`${path}.primary_technique_id:invalid_aadapt_id`);
  }
  const expectedURL = `https://aadapt.mitre.org/techniques/${String(taxonomy.primary_technique_id ?? '')}/`;
  requireValue(taxonomy.primary_technique_url, expectedURL, `${path}.primary_technique_url`, errors);
  nonEmptyString(taxonomy.mapping_rationale, `${path}.mapping_rationale`, errors, 24);
  if (!Array.isArray(taxonomy.secondary_technique_ids)) {
    errors.push(`${path}.secondary_technique_ids:must_be_array`);
  } else {
    const unique = new Set(taxonomy.secondary_technique_ids);
    if (unique.size !== taxonomy.secondary_technique_ids.length) errors.push(`${path}.secondary_technique_ids:duplicates`);
    for (const techniqueID of taxonomy.secondary_technique_ids) {
      if (!techniquePattern.test(String(techniqueID))) errors.push(`${path}.secondary_technique_ids:invalid_aadapt_id`);
    }
  }
}

function verifyClaimBoundary(boundary, errors) {
  const path = 'claim_boundary';
  const keys = [
    'is_execution_evidence',
    'is_validation_result',
    'production_claim_allowed',
    'mainnet_transaction_sent',
    'verdict_authority'
  ];
  if (!exactKeys(boundary, path, keys, errors)) return;
  for (const key of keys) requireValue(boundary[key], false, `${path}.${key}`, errors);
}

function verifyEnvironment(environment, errors) {
  const path = 'environment';
  const keys = [
    'execution_mode',
    'engine',
    'network_access',
    'mainnet_rpc_allowed',
    'ephemeral_generated_signers_only',
    'private_key_material_in_manifest',
    'signature_verification_disabled',
    'arbitrary_account_writes_allowed'
  ];
  if (!exactKeys(environment, path, keys, errors)) return;
  requireValue(environment.execution_mode, 'sandbox', `${path}.execution_mode`, errors);
  requireValue(environment.engine, 'litesvm', `${path}.engine`, errors);
  requireValue(environment.network_access, false, `${path}.network_access`, errors);
  requireValue(environment.mainnet_rpc_allowed, false, `${path}.mainnet_rpc_allowed`, errors);
  requireValue(environment.ephemeral_generated_signers_only, true, `${path}.ephemeral_generated_signers_only`, errors);
  requireValue(environment.private_key_material_in_manifest, false, `${path}.private_key_material_in_manifest`, errors);
  requireValue(environment.signature_verification_disabled, false, `${path}.signature_verification_disabled`, errors);
  requireValue(environment.arbitrary_account_writes_allowed, false, `${path}.arbitrary_account_writes_allowed`, errors);
}

function verifySafetyGates(gates, errors) {
  const path = 'safety_gates';
  const keys = [
    'default_off',
    'owner_approval_required',
    'production_control_mutation',
    'automatic_intervention',
    'wallet_custody',
    'arbitrary_command_execution'
  ];
  if (!exactKeys(gates, path, keys, errors)) return;
  requireValue(gates.default_off, true, `${path}.default_off`, errors);
  requireValue(gates.owner_approval_required, true, `${path}.owner_approval_required`, errors);
  for (const key of ['production_control_mutation', 'automatic_intervention', 'wallet_custody', 'arbitrary_command_execution']) {
    requireValue(gates[key], false, `${path}.${key}`, errors);
  }
}

function verifyControlContract(control, errors) {
  const path = 'control_contract';
  const keys = [
    'control_class',
    'independent_collector_required',
    'adapter_version_required',
    'configuration_hash_required',
    'attack_signal',
    'benign_silence_required'
  ];
  if (!exactKeys(control, path, keys, errors)) return;
  requireValue(control.control_class, 'privileged-transaction-monitor', `${path}.control_class`, errors);
  requireValue(control.independent_collector_required, true, `${path}.independent_collector_required`, errors);
  requireValue(control.adapter_version_required, true, `${path}.adapter_version_required`, errors);
  requireValue(control.configuration_hash_required, true, `${path}.configuration_hash_required`, errors);
  requireValue(control.attack_signal, 'unauthorized_privileged_withdrawal', `${path}.attack_signal`, errors);
  requireValue(control.benign_silence_required, true, `${path}.benign_silence_required`, errors);
}

function verifyStimulus(stimulus, path, errors) {
  if (!exactKeys(stimulus, path, ['program_fixture', 'instruction', 'asset', 'amount_atomic'], errors)) return;
  if (!/^[a-z0-9]+(?:_[a-z0-9]+)*_v\d+$/.test(String(stimulus.program_fixture ?? ''))) {
    errors.push(`${path}.program_fixture:invalid`);
  }
  requireValue(stimulus.instruction, 'treasury_withdrawal', `${path}.instruction`, errors);
  requireValue(stimulus.asset, 'SOL', `${path}.asset`, errors);
  if (!/^[1-9]\d*$/.test(String(stimulus.amount_atomic ?? ''))) errors.push(`${path}.amount_atomic:invalid`);
}

function verifyAuthorization(authorization, kind, path, errors) {
  const keys = ['signer_class', 'approval_state', 'destination_policy', 'production_identity_used'];
  if (!exactKeys(authorization, path, keys, errors)) return;
  requireValue(authorization.signer_class, 'ephemeral_privileged_fixture', `${path}.signer_class`, errors);
  requireValue(authorization.production_identity_used, false, `${path}.production_identity_used`, errors);
  if (kind === 'attack') {
    requireValue(authorization.approval_state, 'absent', `${path}.approval_state`, errors);
    requireValue(authorization.destination_policy, 'not_allowlisted', `${path}.destination_policy`, errors);
  } else if (kind === 'benign') {
    requireValue(authorization.approval_state, 'approved', `${path}.approval_state`, errors);
    requireValue(authorization.destination_policy, 'allowlisted', `${path}.destination_policy`, errors);
  }
}

function verifyAssertions(assertions, path, errors) {
  if (!Array.isArray(assertions) || assertions.length < 2) {
    errors.push(`${path}:invalid_count`);
    return;
  }
  const refs = new Set();
  for (let index = 0; index < assertions.length; index++) {
    const assertion = assertions[index];
    const itemPath = `${path}[${index}]`;
    if (!exactKeys(assertion, itemPath, ['assertion_ref', 'phase', 'subject', 'operator', 'expected'], errors)) continue;
    if (!/^assertion:[a-z0-9]+(?:-[a-z0-9]+)*$/.test(String(assertion.assertion_ref ?? ''))) {
      errors.push(`${itemPath}.assertion_ref:invalid`);
    }
    if (refs.has(assertion.assertion_ref)) errors.push(`${path}:duplicate_assertion_ref`);
    refs.add(assertion.assertion_ref);
    if (!['pre', 'post'].includes(assertion.phase)) errors.push(`${itemPath}.phase:invalid`);
    if (!['treasury_balance_delta_atomic', 'destination_balance_delta_atomic'].includes(assertion.subject)) {
      errors.push(`${itemPath}.subject:invalid`);
    }
    requireValue(assertion.operator, 'equals', `${itemPath}.operator`, errors);
    if (!['zero', 'negative_transfer_amount_atomic', 'positive_transfer_amount_atomic'].includes(assertion.expected)) {
      errors.push(`${itemPath}.expected:invalid`);
    }
  }
}

function verifyExpectedBehavior(behavior, kind, impactDeadlineMS, observationWindowMS, path, errors) {
  if (!exactKeys(behavior, path, ['alert_required', 'expected_signal', 'latest_alert_offset_ms'], errors)) return;
  if (kind === 'attack') {
    requireValue(behavior.alert_required, true, `${path}.alert_required`, errors);
    requireValue(behavior.expected_signal, 'unauthorized_privileged_withdrawal', `${path}.expected_signal`, errors);
    if (!Number.isSafeInteger(behavior.latest_alert_offset_ms) || behavior.latest_alert_offset_ms < 0) {
      errors.push(`${path}.latest_alert_offset_ms:invalid`);
    }
    if (behavior.latest_alert_offset_ms !== impactDeadlineMS) errors.push(`${path}.latest_alert_offset_ms:must_equal_impact_deadline`);
    if (behavior.latest_alert_offset_ms > observationWindowMS) errors.push(`${path}.latest_alert_offset_ms:outside_observation_window`);
  } else {
    requireValue(behavior.alert_required, false, `${path}.alert_required`, errors);
    requireValue(behavior.expected_signal, null, `${path}.expected_signal`, errors);
    requireValue(behavior.latest_alert_offset_ms, null, `${path}.latest_alert_offset_ms`, errors);
  }
}

function verifyCase(item, index, matrixPairRef, errors) {
  const path = `matrix.cases[${index}]`;
  const keys = [
    'case_ref',
    'case_kind',
    'pair_ref',
    'description',
    'stimulus',
    'authorization',
    'planned_operations',
    'state_assertions',
    'impact_deadline_ms',
    'observation_window_ms',
    'expected_control_behavior'
  ];
  if (!exactKeys(item, path, keys, errors)) return;
  if (!/^case:solana:[a-z0-9]+(?:-[a-z0-9]+)*$/.test(String(item.case_ref ?? ''))) errors.push(`${path}.case_ref:invalid`);
  if (!['attack', 'benign'].includes(item.case_kind)) errors.push(`${path}.case_kind:invalid`);
  requireValue(item.pair_ref, matrixPairRef, `${path}.pair_ref`, errors);
  nonEmptyString(item.description, `${path}.description`, errors, 20);
  verifyStimulus(item.stimulus, `${path}.stimulus`, errors);
  verifyAuthorization(item.authorization, item.case_kind, `${path}.authorization`, errors);
  if (!Array.isArray(item.planned_operations) || JSON.stringify(item.planned_operations) !== JSON.stringify(PLANNED_OPERATIONS)) {
    errors.push(`${path}.planned_operations:mismatch`);
  }
  verifyAssertions(item.state_assertions, `${path}.state_assertions`, errors);
  if (!Number.isSafeInteger(item.observation_window_ms) || item.observation_window_ms <= 0) {
    errors.push(`${path}.observation_window_ms:invalid`);
  }
  if (item.case_kind === 'attack') {
    if (!Number.isSafeInteger(item.impact_deadline_ms) || item.impact_deadline_ms < 0 || item.impact_deadline_ms > item.observation_window_ms) {
      errors.push(`${path}.impact_deadline_ms:invalid`);
    }
  } else {
    requireValue(item.impact_deadline_ms, null, `${path}.impact_deadline_ms`, errors);
  }
  verifyExpectedBehavior(
    item.expected_control_behavior,
    item.case_kind,
    item.impact_deadline_ms,
    item.observation_window_ms,
    `${path}.expected_control_behavior`,
    errors
  );
}

function valueAtPath(value, path) {
  return path.split('.').reduce((current, key) => current?.[key], value);
}

function verifyMatrix(matrix, errors) {
  const path = 'matrix';
  if (!exactKeys(matrix, path, ['pair_ref', 'matched_fields', 'single_intent_difference', 'cases'], errors)) return;
  if (!/^pair:solana:[a-z0-9]+(?:-[a-z0-9]+)*$/.test(String(matrix.pair_ref ?? ''))) errors.push(`${path}.pair_ref:invalid`);
  exactSet(matrix.matched_fields, `${path}.matched_fields`, MATCHED_FIELDS, errors);
  requireValue(matrix.single_intent_difference, 'authorization_and_destination_policy', `${path}.single_intent_difference`, errors);
  if (!Array.isArray(matrix.cases) || matrix.cases.length !== 2) {
    errors.push(`${path}.cases:must_contain_exactly_two`);
    return;
  }
  matrix.cases.forEach((item, index) => verifyCase(item, index, matrix.pair_ref, errors));
  const attackCases = matrix.cases.filter(item => item?.case_kind === 'attack');
  const benignCases = matrix.cases.filter(item => item?.case_kind === 'benign');
  if (attackCases.length !== 1 || benignCases.length !== 1) errors.push(`${path}.cases:requires_one_attack_and_one_benign`);
  if (new Set(matrix.cases.map(item => item?.case_ref)).size !== matrix.cases.length) errors.push(`${path}.cases:duplicate_case_ref`);
  if (attackCases.length !== 1 || benignCases.length !== 1) return;
  const attack = attackCases[0];
  const benign = benignCases[0];
  for (const field of MATCHED_FIELDS) {
    if (valueAtPath(attack, field) !== valueAtPath(benign, field)) errors.push(`${path}.cases:matched_field_mismatch:${field}`);
  }
  if (JSON.stringify(attack.planned_operations) !== JSON.stringify(benign.planned_operations)) {
    errors.push(`${path}.cases:planned_operations_mismatch`);
  }
  if (JSON.stringify(attack.state_assertions) !== JSON.stringify(benign.state_assertions)) {
    errors.push(`${path}.cases:state_assertions_mismatch`);
  }
}

function verifyLimitations(limitations, errors) {
  if (!Array.isArray(limitations) || limitations.length < 3) {
    errors.push('limitations:minimum_three_required');
    return;
  }
  if (new Set(limitations).size !== limitations.length) errors.push('limitations:duplicates');
  limitations.forEach((item, index) => nonEmptyString(item, `limitations[${index}]`, errors, 12));
  const combined = limitations.join(' ').toLowerCase();
  for (const phrase of ['no transaction', 'no defense control', 'not implemented']) {
    if (!combined.includes(phrase)) errors.push(`limitations:missing_boundary:${phrase.replaceAll(' ', '_')}`);
  }
}

function verifyReferences(references, errors) {
  if (!Array.isArray(references) || references.length !== 3) {
    errors.push('references:must_contain_exactly_three');
    return;
  }
  const roles = new Set();
  references.forEach((reference, index) => {
    const path = `references[${index}]`;
    if (!exactKeys(reference, path, ['role', 'title', 'url'], errors)) return;
    if (!['taxonomy', 'methodology', 'execution-engine'].includes(reference.role)) errors.push(`${path}.role:invalid`);
    if (roles.has(reference.role)) errors.push(`references:duplicate_role:${String(reference.role)}`);
    roles.add(reference.role);
    nonEmptyString(reference.title, `${path}.title`, errors, 4);
    if (typeof reference.url !== 'string' || !reference.url.startsWith('https://')) errors.push(`${path}.url:must_be_https`);
  });
  for (const role of ['taxonomy', 'methodology', 'execution-engine']) {
    if (!roles.has(role)) errors.push(`references:missing_role:${role}`);
  }
}

export function verifyDefenseScenarioObject(manifest) {
  const errors = [];
  if (!isObject(manifest)) return { ok: false, errors: ['manifest:must_be_object'] };
  walkForbiddenFields(manifest, 'manifest', errors);
  exactKeys(manifest, 'manifest', TOP_LEVEL_KEYS, errors);
  if (typeof manifest.$schema !== 'string' || !manifest.$schema.endsWith('defense-validation-scenario-v0.1.schema.json')) {
    errors.push('manifest.$schema:unsupported');
  }
  requireValue(manifest.contract, DEFENSE_SCENARIO_CONTRACT, 'manifest.contract', errors);
  if (!/^scenario:solana:[a-z0-9]+(?:-[a-z0-9]+)*$/.test(String(manifest.scenario_ref ?? ''))) {
    errors.push('manifest.scenario_ref:invalid');
  }
  if (!/^v\d+\.\d+\.\d+$/.test(String(manifest.scenario_version ?? ''))) errors.push('manifest.scenario_version:invalid');
  nonEmptyString(manifest.title, 'manifest.title', errors, 12);
  requireValue(manifest.status, 'planned', 'manifest.status', errors);
  requireValue(manifest.chain, 'solana', 'manifest.chain', errors);
  requireValue(manifest.ruleset_version, DEFENSE_VALIDATION_RULESET, 'manifest.ruleset_version', errors);
  verifyTaxonomy(manifest.taxonomy, errors);
  verifyClaimBoundary(manifest.claim_boundary, errors);
  verifyEnvironment(manifest.environment, errors);
  verifySafetyGates(manifest.safety_gates, errors);
  verifyControlContract(manifest.control_contract, errors);
  verifyMatrix(manifest.matrix, errors);
  exactSet(manifest.required_run_evidence, 'required_run_evidence', REQUIRED_RUN_EVIDENCE, errors);
  verifyLimitations(manifest.limitations, errors);
  verifyReferences(manifest.references, errors);
  const uniqueErrors = [...new Set(errors)].sort();
  return {
    ok: uniqueErrors.length === 0,
    errors: uniqueErrors,
    scenario_ref: String(manifest.scenario_ref ?? ''),
    scenario_version: String(manifest.scenario_version ?? ''),
    status: String(manifest.status ?? '')
  };
}

export async function verifyDefenseScenarioFile(path) {
  const raw = await readFile(path, 'utf8');
  return verifyDefenseScenarioObject(JSON.parse(raw));
}

async function main() {
  const paths = process.argv.slice(2);
  if (paths.length === 0) throw new Error('usage: verify-defense-scenario.mjs <scenario.json> [...]');
  let failed = false;
  for (const path of paths) {
    const result = await verifyDefenseScenarioFile(path);
    process.stdout.write(`${JSON.stringify({ path, ...result })}\n`);
    if (!result.ok) failed = true;
  }
  if (failed) process.exitCode = 1;
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main().catch(error => {
    process.stderr.write(`${JSON.stringify({ ok: false, errors: [String(error?.message || error)] })}\n`);
    process.exitCode = 1;
  });
}
