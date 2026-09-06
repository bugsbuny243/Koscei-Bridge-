'use strict';

const fs = require('fs');
const path = require('path');

const baseURL = String(process.env.BASE_URL || 'https://tradepigloball.co').replace(/\/$/, '');
const mint = String(process.env.KOSCHEI_FULL_SCAN_MINT || 'HHPpU9u56Bwxov12nf7DXUCuv6h1q5j1xgGS3yukpump').trim();
const outputDir = path.resolve(process.env.OUTPUT_DIR || 'diagnostics');
const timeoutMs = Number(process.env.DRIVE_MEMORY_SCAN_TIMEOUT_MS || 300000);

function requireObject(value, label) {
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error(`${label}_missing`);
  return value;
}

async function main() {
  if (!mint) throw new Error('drive_memory_scan_mint_missing');
  fs.mkdirSync(outputDir, { recursive: true });

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(new Error('drive_memory_scan_timeout')), timeoutMs);
  const startedAt = Date.now();
  let response;
  try {
    response = await fetch(`${baseURL}/api/token/scan`, {
      method: 'POST',
      headers: {
        accept: 'application/json',
        'content-type': 'application/json',
        'user-agent': 'koschei-production-drive-memory-acceptance/1.0.0',
      },
      body: JSON.stringify({ mint, network: 'solana-mainnet' }),
      signal: controller.signal,
    });
  } finally {
    clearTimeout(timer);
  }

  const raw = await response.text();
  fs.writeFileSync(path.join(outputDir, 'drive-memory-http-status.txt'), `${response.status}\n`);
  fs.writeFileSync(path.join(outputDir, 'drive-memory-response.json'), raw);
  if (!response.ok) throw new Error(`drive_memory_scan_http_${response.status}`);

  let payload;
  try {
    payload = JSON.parse(raw);
  } catch (error) {
    throw new Error(`drive_memory_scan_invalid_json:${error.message}`);
  }

  const report = requireObject(payload.investigation_report, 'investigation_report');
  const receipt = requireObject(report.intelligence_memory, 'intelligence_memory');
  if (receipt.backend !== 'google_drive') throw new Error(`drive_memory_backend_unexpected:${String(receipt.backend || '')}`);
  if (typeof receipt.durable !== 'boolean') throw new Error('drive_memory_durable_not_boolean');

  const allowedStatuses = new Set(['drive_archived', 'drive_unavailable', 'drive_write_failed', 'encode_failed']);
  if (!allowedStatuses.has(String(receipt.status || ''))) {
    throw new Error(`drive_memory_status_unexpected:${String(receipt.status || '')}`);
  }

  const configurationStatus = String(receipt.configuration_status || '');
  const allowedConfigurationStatuses = new Set([
    'ready',
    'configured',
    'credential_missing',
    'folder_missing',
    'folder_and_credential_missing',
    'credential_invalid_or_incomplete',
  ]);
  if (!allowedConfigurationStatuses.has(configurationStatus)) {
    throw new Error(`drive_memory_configuration_status_unexpected:${configurationStatus}`);
  }

  if (receipt.status === 'drive_archived') {
    if (receipt.durable !== true) throw new Error('drive_archived_without_durable_true');
    if (configurationStatus !== 'ready') throw new Error('drive_archived_without_ready_configuration');
    const object = requireObject(receipt.object, 'intelligence_memory_object');
    if (!String(object.id || '').trim()) throw new Error('drive_object_id_missing');
    if (!String(object.name || '').trim()) throw new Error('drive_object_name_missing');
    if (!/^sha256:[a-f0-9]{64}$/i.test(String(object.sha256 || ''))) throw new Error('drive_object_sha256_invalid');
  } else if (receipt.durable !== false) {
    throw new Error('non_archived_memory_claimed_durable');
  }

  const artifact = {
    schema_version: 'koschei-production-drive-memory-acceptance-v1',
    generated_at: new Date().toISOString(),
    elapsed_ms: Date.now() - startedAt,
    target: mint,
    endpoint: `${baseURL}/api/token/scan`,
    http_status: response.status,
    receipt: {
      status: receipt.status,
      durable: receipt.durable,
      backend: receipt.backend,
      configuration_status: configurationStatus,
      object: receipt.object || null,
    },
  };
  fs.writeFileSync(path.join(outputDir, 'drive-memory-result.json'), `${JSON.stringify(artifact, null, 2)}\n`);

  console.log(`DRIVE_MEMORY_HTTP_STATUS=${response.status}`);
  console.log(`DRIVE_MEMORY_STATUS=${receipt.status}`);
  console.log(`DRIVE_MEMORY_DURABLE=${receipt.durable}`);
  console.log(`DRIVE_MEMORY_BACKEND=${receipt.backend}`);
  console.log(`DRIVE_MEMORY_CONFIGURATION_STATUS=${configurationStatus}`);
  console.log('PRODUCTION_DRIVE_MEMORY_PROBE_ACCEPTED=true');
}

main().catch((error) => {
  fs.mkdirSync(outputDir, { recursive: true });
  fs.writeFileSync(path.join(outputDir, 'drive-memory-probe-error.txt'), `${error.stack || error.message || String(error)}\n`);
  console.error(`PRODUCTION_DRIVE_MEMORY_PROBE_FAILURE: ${error.stack || error.message || String(error)}`);
  process.exit(1);
});
