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
requireText(reportsHTML,'/js/customer-reports-v2.js?v=1','reports html');
requireText(watchHTML,'/js/customer-watchlist-v2.js?v=1','watchlist html');
requireText(reportsHTML,'Missing service data remains unavailable','reports truth boundary');
requireText(watchHTML,'does not rewrite older evidence','monitoring truth boundary');

requireText(reportsJS,"KoscheiAuth.apiCall('/api/auth/premium-access'",'reports access source');
requireText(reportsJS,"KoscheiAuth.apiCall('/api/v1/unified/reports'",'reports vault source');
requireText(reportsJS,"accessData.access?.active!==true",'reports access gate');
requireText(reportsJS,"signed?'SIGNED':'DURABLE'",'signature-aware evidence state');
requireText(reportsJS,"esc(floor??'—')",'structural-floor escaping');
requireText(reportsJS,"kind==='wallet'",'wallet continuation');
requireText(reportsJS,"kind==='site'||kind==='url'",'site continuation');

requireText(watchJS,"api('/api/watchlist')",'watchlist source');
requireText(watchJS,"api('/api/watchlist/alerts')",'watchlist alerts source');
requireText(watchJS,"api('/api/watchlist/refresh?limit=5'",'bounded refresh source');
requireText(watchJS,"target_type:'token'",'watch target contract');
requireText(watchJS,"network:'solana-mainnet'",'watch network contract');
requireText(watchJS,"!text(item?.read_at)",'unread alert handling');
requireText(watchJS,"encodeURIComponent(text(item.id))",'watch id encoding');
requireText(watchJS,"confirm(`Remove",'destructive remove confirmation');

for(const [js,label] of [[reportsJS,'reports js'],[watchJS,'watchlist js']]){
  if(js.includes('Math.random('))throw new Error(`${label}: must not fabricate operational metrics`);
  if(/\bfetch\s*\(/.test(js))throw new Error(`${label}: account data must flow through KoscheiAuth.apiCall`);
}
if(/[İıŞşĞğÇçÖöÜü]/.test(watchHTML))throw new Error('watchlist html: public operations surface must not drift back to mixed Turkish/English copy');
requireText(css,'.ops-record','shared record styles');
requireText(css,'.ops-monitor-card','monitoring card styles');
requireText(css,'.ops-kpis','operations KPI styles');
console.log('customer operations v2 contract: ok');
