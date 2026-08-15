const fs = require('fs');

const source = fs.readFileSync('public/js/security-radar-detail.js', 'utf8');
const required = [
  'normalizeCustomerInvestigation',
  'envelope?.investigation_report',
  'renderDetail(report',
  'UNIFIED GRADE',
  'CANONICAL KOSCHEI VERDICT',
  'security_unified_radar_verdicts',
  'recursive_lineage',
  'triggered_rules',
  'watch_flags',
  'decision_path',
  'access.plan',
  'outputs_remaining'
];
for (const marker of required) {
  if (!source.includes(marker)) throw new Error(`missing canonical customer investigation UI marker: ${marker}`);
}

const forbidden = [
  'risk_index',
  'token_tier',
  'structural_floor',
  'KOSCH doğrulaması gerekli',
  'Temsilci risk'
];
for (const marker of forbidden) {
  if (source.includes(marker)) throw new Error(`legacy customer investigation UI contract returned: ${marker}`);
}

const postBlock = source.slice(source.indexOf("api('/api/v1/radar/check'"), source.indexOf('async function boot'));
if (!postBlock.includes('normalizeCustomerInvestigation(data, target)')) {
  throw new Error('POST response is not consumed as a canonical investigation report');
}
if (!postBlock.includes('renderDetail(report')) {
  throw new Error('canonical investigation report is not rendered directly');
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
console.log('canonical customer and owner investigation UI contracts verified');
