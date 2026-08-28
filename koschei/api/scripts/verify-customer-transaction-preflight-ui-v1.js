const fs = require('fs');

const overlay = fs.readFileSync('public/js/customer-transaction-preflight-v1.js', 'utf8');
const scan = fs.readFileSync('public/scan.html', 'utf8');
const command = fs.readFileSync('public/js/customer-command-center-v1.js', 'utf8');
new Function(overlay);

const required = [
  '/api/customer/web3/transaction-preflight',
  "credentials:'same-origin'",
  "event.stopImmediatePropagation()",
  "form.addEventListener('submit'",
  'data-customer-transaction-preflight-result',
  'guard_complete',
  'program_policy',
  'intent_policy',
  'automatic_decode_complete',
  'cpi_asset_flow_complete',
  'authority_surface_complete',
  'threat_history_complete',
  'WITHHOLD — EVIDENCE INCOMPLETE',
  'Numeric risk scores are not the authority',
  "transaction.value=''"
];
for (const marker of required) {
  if (!overlay.includes(marker)) throw new Error(`missing customer preflight UI marker: ${marker}`);
}
for (const forbidden of [
  '/api/public/transaction-simulate',
  'localStorage',
  'sessionStorage',
  'X-API-Key',
  'Authorization: Bearer'
]) {
  if (overlay.includes(forbidden)) throw new Error(`customer preflight UI violates boundary: ${forbidden}`);
}
if (!overlay.includes("},true);")) throw new Error('transaction submit interception must run in capture phase');
if (!scan.includes('/js/customer-transaction-preflight-v1.js?v=1')) {
  throw new Error('scan page does not mount the Professional transaction preflight overlay');
}
if (!scan.includes('Transaction Preflight') || !scan.includes('Professional+ before signing')) {
  throw new Error('scan page does not label the Professional transaction capability truthfully');
}
if (!command.includes("{label:'Transaction Preflight',href:'/scan?mode=transaction',access:'PROFESSIONAL+'}")) {
  throw new Error('customer command center is missing the Professional Transaction Preflight capability');
}
console.log('customer transaction preflight UI v1 contract verified');
