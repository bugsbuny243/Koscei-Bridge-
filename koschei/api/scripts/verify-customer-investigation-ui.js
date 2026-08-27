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
console.log('customer and owner investigation UI contracts verified');
