'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const reportsHTML=fs.readFileSync(path.join(root,'public','reports.html'),'utf8');
const watchHTML=fs.readFileSync(path.join(root,'public','watchlist.html'),'utf8');
const reportsJS=fs.readFileSync(path.join(root,'public','js','customer-reports-v2.js'),'utf8');
const watchJS=fs.readFileSync(path.join(root,'public','js','customer-watchlist-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','customer-operations-v2.css'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}

for(const [html,label] of [[reportsHTML,'reports html'],[watchHTML,'watchlist html']]){
  requireText(html,'<html lang="en">',label);
  requireText(html,'/css/customer-operations-v2.css?v=1',label);
}
requireText(reportsHTML,'/js/customer-reports-v2.js?v=2','reports html');
requireText(watchHTML,'/js/customer-watchlist-v2.js?v=2','watchlist html');
requireText(reportsHTML,'History without invented evidence.','reports truth boundary');
requireText(reportsHTML,'reading history does not consume a scan unit','reports read-only quota boundary');
requireText(watchHTML,'does not rewrite older evidence','monitoring truth boundary');
requireText(watchHTML,'Professional plan or higher','watchlist Professional SaaS boundary');
if(/KOSCH tier|holder tier|Pro tier or higher/i.test(watchHTML))throw new Error('watchlist html: legacy token-tier access copy is forbidden');

requireText(reportsJS,"KoscheiAuth.apiCall('/api/v1/radar/jobs/'",'canonical investigation history source');
requireText(reportsJS,"data?.schema_version!=='koschei-customer-investigation-history-v1'",'history schema gate');
requireText(reportsJS,"data?.source!=='web3_jobs'",'history durable source gate');
requireText(reportsJS,"data?.job_type!=='canonical_investigation'",'history canonical job type gate');
requireText(reportsJS,"signed===true&&signature&&ruleset",'strict signature gate');
requireText(reportsJS,"signed===true)return {kind:'incomplete',label:'SIGNATURE INCOMPLETE'}",'incomplete signature state');
requireText(reportsJS,"if(!Array.isArray(history))",'history unavailable-not-empty boundary');
requireText(reportsJS,"setUnavailableKPIs('Canonical investigation history unavailable; no history count inferred.')",'history unavailable-not-zero KPI boundary');
requireText(reportsJS,"KoscheiAuth.requireAuth('/login.html')",'canonical login continuation');
if(reportsJS.includes('/api/v1/unified/reports'))throw new Error('reports js: must not call removed unified-reports frontend contract');
if(reportsJS.includes('/api/v1/investigations/history'))throw new Error('reports js: must use canonical radar jobs history collection');
if(reportsJS.includes('.innerHTML='))throw new Error('reports js: canonical history must use DOM/textContent rendering');

requireText(watchJS,"api('/api/watchlist')",'watchlist source');
requireText(watchJS,"api('/api/watchlist/alerts')",'watchlist alerts source');
requireText(watchJS,"api('/api/watchlist/refresh?limit=5'",'bounded refresh source');
requireText(watchJS,"target_type:'token'",'watch target contract');
requireText(watchJS,"network:'solana-mainnet'",'watch network contract');
requireText(watchJS,"if(raw==='new')return'unread';if(raw==='read')return'read';return'unknown'",'authoritative unread alert handling');
requireText(watchJS,"encodeURIComponent(id)",'watch id encoding');
requireText(watchJS,"window.confirm(`Remove",'destructive remove confirmation');
requireText(watchJS,"targets=Array.isArray(targetData?.targets)?targetData.targets:null",'watchlist unavailable-not-empty boundary');
requireText(watchJS,"alerts=Array.isArray(alertData?.alerts)?alertData.alerts:null",'watchlist alert unavailable-not-empty boundary');
requireText(watchJS,"setTargetKPIsUnavailable('Monitoring target collection unavailable; no target state inferred.')",'watchlist target unavailable-not-zero boundary');
requireText(watchJS,"setAlertKPIUnavailable('Alert collection unavailable; no unread count inferred.')",'watchlist alert unavailable-not-zero boundary');
requireText(watchJS,"load({preserveStatus:true})",'action feedback preservation');
if(watchJS.includes('.innerHTML='))throw new Error('watchlist js: API data must use DOM/textContent rendering');
if(/Pro KOSCH|token tier|holder tier/i.test(watchJS))throw new Error('watchlist js: legacy token-tier access messaging is forbidden');

for(const [js,label] of [[reportsJS,'reports js'],[watchJS,'watchlist js']]){
  if(js.includes('Math.random('))throw new Error(`${label}: must not fabricate operational metrics`);
  if(/\bfetch\s*\(/.test(js))throw new Error(`${label}: account data must flow through KoscheiAuth.apiCall`);
}
if(/[İıŞşĞğÇçÖöÜü]/.test(watchHTML))throw new Error('watchlist html: public operations surface must not drift back to mixed Turkish/English copy');
requireText(css,'.ops-record','shared record styles');
requireText(css,'.ops-monitor-card','monitoring card styles');
requireText(css,'.ops-kpis','operations KPI styles');
console.log('customer operations v2 contract: ok');
