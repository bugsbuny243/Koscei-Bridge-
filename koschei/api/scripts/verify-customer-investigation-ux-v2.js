'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const html=fs.readFileSync(path.join(root,'public','scan.html'),'utf8');
const ux=fs.readFileSync(path.join(root,'public','js','customer-investigation-ux-v2.js'),'utf8');
const premium=fs.readFileSync(path.join(root,'public','js','customer-arvis-premium-suite.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','customer-investigation-ux-v2.css'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}

requireText(html,'/css/koschei.css?v=1','scan html');
requireText(html,'/js/customer-investigation-ux-v2.js?v=1','scan html');
requireText(html,'/js/customer-arvis-premium-suite.js?v=2','scan html premium cache key');
requireText(ux,'ALLOW is not a safety guarantee','allow boundary');
requireText(ux,'Full technical evidence','technical disclosure');
requireText(ux,'Source evidence panels','source disclosure');
requireText(ux,"details.appendChild(grid)",'premium grid preservation');
requireText(ux,"body.appendChild(node)",'source panel preservation');
requireText(ux,"'.public-investigation-card,#lp-control-evidence,.lp-control-card,#full-scan-live-evidence,.live-evidence-card'",'source panel selector');
requireText(ux,'WHAT MATTERS NOW','customer hierarchy');
requireText(ux,'WHAT IS UNRESOLVED','unresolved hierarchy');
requireText(premium,'customerPayloadKey','idempotent premium mount');
requireText(premium,'existing.dataset.customerPayloadKey===key','same-payload remount guard');
requireText(premium,'koschei:customer-premium-mounted','customer mount event');
requireText(premium,"value.includes('/api/arvis/preflight')",'quick-scan stale payload guard');
requireText(premium,"value.includes('/api/public/transaction-simulate')",'transaction stale payload guard');
requireText(premium,"latestPayload=null",'stale premium payload clear');
requireText(css,'.customer-result-summary','summary styles');
requireText(css,'.customer-full-technical','technical disclosure styles');
requireText(css,'.customer-source-panels','source disclosure styles');

const publicScanIndex=html.indexOf('/js/public-solana-scan.js?v=12');
const uxIndex=html.indexOf('/js/customer-investigation-ux-v2.js?v=1');
if(publicScanIndex<0||uxIndex<publicScanIndex)throw new Error('scan html: customer UX v2 must load after public scan renderer');

if(/verdict_authority\s*=\s*true|grade_authority\s*=\s*true/.test(ux))throw new Error('customer UI must not grant verdict or grade authority');
if(ux.includes('.removeChild(grid)')||ux.includes('grid.remove()'))throw new Error('premium evidence grid must be moved into disclosure, not deleted');
console.log('customer investigation UX v2 contract: ok');
