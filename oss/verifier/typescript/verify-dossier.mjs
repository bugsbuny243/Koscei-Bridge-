#!/usr/bin/env node

import { createHash } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';

export const DOSSIER_ROW_IDS = [
  'launch','mint','freeze','wash','address','liquidity','funding','concentration','sniper','first-buyer',
  'track','creator-sell','dominant-exit','liq-move','program','metadata','claim','mev','distribution','signed'
];

export const ACTOR_DOSSIER_ROW_IDS = Array.from({ length: 10 }, (_, index) => `AC-${String(index + 1).padStart(2, '0')}`);

const sha256Hex = value => createHash('sha256').update(value).digest('hex');
const strings = value => Array.isArray(value) ? value.map(item => String(item ?? '').trim()).filter(Boolean) : [];
const positiveSlots = value => Array.isArray(value) ? value.map(Number).filter(item => Number.isSafeInteger(item) && item > 0) : [];

function base32NoPadding(bytes) {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  let bits = 0;
  let buffer = 0;
  let output = '';
  for (const byte of bytes) {
    buffer = (buffer << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      output += alphabet[(buffer >>> bits) & 31];
    }
  }
  if (bits > 0) output += alphabet[(buffer << (5 - bits)) & 31];
  return output;
}

export function dossierCaseRef(targetID, snapshotIdentity) {
  const digest = createHash('sha256').update(`${String(targetID ?? '').trim()}\n${String(snapshotIdentity ?? '').trim()}`).digest();
  return `KD1-${base32NoPadding(digest.subarray(0, 20)).toLowerCase()}`;
}

function refsPresent(refs) {
  refs = refs && typeof refs === 'object' && !Array.isArray(refs) ? refs : {};
  return strings(refs.wallets).length + strings(refs.accounts).length + strings(refs.signatures).length + positiveSlots(refs.slots).length + strings(refs.evidence_keys).length > 0;
}

function verifyRows(bundle, errors) {
  const targetKind = String(bundle.target?.kind ?? (bundle.token?.mint ? 'token_mint' : '')).trim();
  const expectedIDs = targetKind === 'wallet' ? ACTOR_DOSSIER_ROW_IDS : DOSSIER_ROW_IDS;
  const rows = bundle.verdict_card?.signal_rows;
  if (!Array.isArray(rows) || rows.length !== expectedIDs.length) {
    errors.push('signal_row_count_mismatch');
    return;
  }
  const ids = rows.map(row => String(row?.id ?? ''));
  if (new Set(ids).size !== ids.length) errors.push('duplicate_signal_row_id');
  for (let index = 0; index < expectedIDs.length; index++) {
    if (ids[index] !== expectedIDs[index]) errors.push(`signal_row_order_mismatch:${index}`);
  }
  for (const row of rows) {
    const state = String(row?.state ?? '');
    if ((state === 'verified' || state === 'observed') && !refsPresent(row?.refs)) {
      errors.push(`populated_signal_missing_refs:${String(row?.id ?? '')}`);
    }
    if (targetKind === 'wallet') {
      const acceptanceStatus = String(row?.acceptance_status ?? '');
      if (!['pass', 'fail', 'not_investigated'].includes(acceptanceStatus)) {
        errors.push(`actor_acceptance_status_invalid:${String(row?.id ?? '')}`);
      }
      if (!Array.isArray(row?.limitations)) {
        errors.push(`actor_limitations_missing:${String(row?.id ?? '')}`);
      }
    }
  }
}

export function verifyDossierObject(bundle) {
  const errors = [];
  if (!bundle || typeof bundle !== 'object' || Array.isArray(bundle)) return { ok: false, errors: ['bundle_must_be_object'] };
  if (bundle.dossier_version !== 'koschei-dossier-v1') errors.push('unsupported_dossier_version');

  const expectedHash = String(bundle.bundle_hash ?? '');
  const body = { ...bundle };
  delete body.bundle_hash;
  const actualHash = `sha256:${sha256Hex(Buffer.from(JSON.stringify(body), 'utf8'))}`;
  if (expectedHash !== actualHash) errors.push('bundle_hash_mismatch');

  const targetID = bundle.target?.id || bundle.token?.mint;
  const verdictSignature = bundle.verification?.verdict_signature || bundle.verdict?.signature;
  const snapshotIdentity = bundle.verification?.snapshot_identity || verdictSignature;
  const expectedCaseRef = dossierCaseRef(targetID, snapshotIdentity);
  if (bundle.case_ref !== expectedCaseRef) errors.push('case_ref_mismatch');

  verifyRows(bundle, errors);

  const targetKind = String(bundle.target?.kind ?? (bundle.token?.mint ? 'token_mint' : '')).trim();
  if (targetKind === 'wallet') {
    if (!bundle.actor_acceptance || typeof bundle.actor_acceptance !== 'object') errors.push('actor_acceptance_missing');
    if (!Array.isArray(bundle.evidence_log)) errors.push('actor_evidence_log_missing');
    if (!bundle.section_limitations || typeof bundle.section_limitations !== 'object') errors.push('actor_section_limitations_missing');
  }

  if (!Array.isArray(bundle.limitations) || bundle.limitations.length < 3) errors.push('limitations_missing');
  if (!String(bundle.source_snapshot_hash ?? '').match(/^sha256:[0-9a-f]{64}$/)) errors.push('source_snapshot_hash_invalid');
  return { ok: errors.length === 0, errors, case_ref: bundle.case_ref, bundle_hash: expectedHash, actual_hash: actualHash };
}

export async function verifyDossierFile(path) {
  const raw = await readFile(path, 'utf8');
  return verifyDossierObject(JSON.parse(raw));
}

async function main() {
  const path = process.argv[2];
  if (!path) throw new Error('usage: verify-dossier.mjs <dossier.json>');
  const result = await verifyDossierFile(path);
  process.stdout.write(`${JSON.stringify(result)}\n`);
  if (!result.ok) process.exitCode = 1;
}

if (import.meta.url === pathToFileURL(process.argv[1] || '').href) {
  main().catch(error => {
    process.stderr.write(`${JSON.stringify({ ok: false, errors: [String(error?.message || error)] })}\n`);
    process.exitCode = 1;
  });
}
