const fs = require('fs');

const source = fs.readFileSync('public/js/security-radar-detail.js', 'utf8');
const required = [
  'normalizeCustomerInvestigation',
  'envelope?.investigation_report',
  'renderDetail(directReport',
  'lpControlPanel(data.lp_control)',
  'liveEvidencePanel(data.full_scan_live_evidence)',
  'behaviorPanel(data.behavior_signals)',
  'UNIFIED GRADE',
  'EVIDENCE PENDING'
];
for (const marker of required) {
  if (!source.includes(marker)) throw new Error(`missing customer investigation UI marker: ${marker}`);
}
const postBlock = source.slice(source.indexOf("api('/api/v1/radar/check'"), source.indexOf('async function boot'));
if (!postBlock.includes('data.investigation_report') && !postBlock.includes('normalizeCustomerInvestigation(data, target)')) {
  throw new Error('POST response is not consumed as an investigation report');
}
if (postBlock.indexOf('renderDetail(directReport') > postBlock.indexOf('await openDetail(target, item)')) {
  throw new Error('direct investigation rendering must precede legacy detail fallback');
}

const customerPremium = fs.readFileSync('public/js/customer-arvis-premium-suite.js', 'utf8');
const attackPathMarkers = [
  'mountAttackPath',
  'report.attack_path',
  'attack.evidence_references',
  'data-arvis-attack-path',
  'ATTACK PATH → CONCRETE EVIDENCE',
  'Kapasite, niyet kanıtı değildir.'
];
for (const marker of attackPathMarkers) {
  if (!customerPremium.includes(marker)) throw new Error(`missing customer attack-path UI marker: ${marker}`);
}
if (customerPremium.includes("fetch('/api/v1/radar/detail") || customerPremium.includes("fetch('/api/v1/radar/check")) {
  throw new Error('attack-path renderer must reuse the canonical customer payload instead of starting a duplicate investigation request');
}

const ownerHTML = fs.readFileSync('public/owner-production.html', 'utf8');
const ownerCreator = fs.readFileSync('public/js/owner-creator-intelligence.js', 'utf8');
const ownerControlIndex = ownerHTML.indexOf('owner-control-center.js');
const creatorIndex = ownerHTML.indexOf('owner-creator-intelligence.js');
const courtIndex = ownerHTML.indexOf('owner-court-ui.js');
const ownerAIIndex = ownerHTML.indexOf('owner-ai-chat.js');
if ([ownerControlIndex, creatorIndex, courtIndex, ownerAIIndex].some(index => index < 0)) {
  throw new Error('owner production page is missing canonical investigation scripts');
}
if (!(ownerControlIndex < creatorIndex && creatorIndex < courtIndex && courtIndex < ownerAIIndex)) {
  throw new Error('owner canonical script order is invalid');
}
const ownerMarkers = [
  'creator_intelligence',
  'creator_distribution',
  'actor_investigation',
  'created_mint_portfolio',
  'verified_candidates',
  'funding_origin',
  'recipients',
  'renderUnified',
  'OwnerRadarKit'
];
for (const marker of ownerMarkers) {
  if (!ownerCreator.includes(marker)) throw new Error(`missing owner creator intelligence marker: ${marker}`);
}
if (ownerCreator.includes('/api/owner/defense/investigate') || ownerCreator.includes('/api/owner/defense/distribution')) {
  throw new Error('owner creator renderer must not start a duplicate actor investigation request');
}

const ownerServer = fs.readFileSync('internal/http/server.go', 'utf8');
const ownerLab = fs.readFileSync('public/js/owner-web3-lab.js', 'utf8');
const ownerSocial = fs.readFileSync('public/js/owner-social-studio.js', 'utf8');
new Function(ownerLab);
new Function(ownerSocial);

const ownerWeb3Routes = [
  '/api/owner/web3/shield/preflight',
  '/api/owner/web3/transaction-guard',
  '/api/owner/web3/defense-validation',
  '/api/owner/web3/execution-assurance/safe/verify'
];
for (const route of ownerWeb3Routes) {
  if (!ownerServer.includes(`mux.HandleFunc("${route}", requiresDB(h, ownerOnly(h,`)) {
    throw new Error(`owner Web3 route is not protected by the owner-only boundary: ${route}`);
  }
  if (!ownerLab.includes(route)) throw new Error(`owner Web3 lab is missing route: ${route}`);
}
if (ownerLab.includes("'/api/v1/") || ownerLab.includes('"/api/v1/')) {
  throw new Error('owner Web3 lab must not call API-key protected public developer routes directly');
}

const ownerLabMarkers = [
  'Owner Web3 Validation Lab',
  'Shield Preflight',
  'Transaction Guard V2',
  'Defense Validation',
  'Safe Execution Assurance',
  'sanitizeSocialResult',
  'owner_web3_evidence',
  'attack_path',
  'program_policy',
  'intent_policy',
  'recordVideo',
  'canvasBlob',
  'koschei:owner-web3-result'
];
for (const marker of ownerLabMarkers) {
  if (!ownerLab.includes(marker)) throw new Error(`missing owner Web3 lab marker: ${marker}`);
}
const sanitizeStart = ownerLab.indexOf('function sanitizeSocialResult');
const sanitizeEnd = ownerLab.indexOf('function socialPayload', sanitizeStart);
if (sanitizeStart < 0 || sanitizeEnd <= sanitizeStart) throw new Error('owner Web3 social sanitizer contract is missing');
const sanitizeBlock = ownerLab.slice(sanitizeStart, sanitizeEnd);
for (const forbidden of ['canonical_base64', 'execution_proof', 'proof_attestation', 'transaction:']) {
  if (sanitizeBlock.includes(forbidden)) throw new Error(`raw request material leaked into owner social sanitizer: ${forbidden}`);
}
if (ownerLab.includes('latestRequest') || ownerLab.includes('requestPayload')) {
  throw new Error('owner Web3 lab must not retain raw validation requests in shared state');
}

const ownerSocialMarkers = [
  '/js/owner-web3-lab.js?v=1',
  'latestSocialPayload',
  'owner_web3_evidence',
  'OWNER_EVIDENCE_STUDIO_REQUEST',
  'lab().drawMediaCanvas',
  'lab().recordVideo',
  'lab().canvasBlob',
  'Video / Reels oluştur',
  'Gönderi / X görselini indir',
  'Raw serialized transaction, execution proof ve canonical action sosyal pakete taşınmaz.'
];
for (const marker of ownerSocialMarkers) {
  if (!ownerSocial.includes(marker)) throw new Error(`missing owner evidence studio marker: ${marker}`);
}
if (ownerSocial.includes('X-API-Key') || ownerSocial.includes('Authorization: Bearer')) {
  throw new Error('owner social studio must never embed developer API credentials');
}

console.log('customer and owner investigation UI contracts verified');