'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const cases=fs.readFileSync(path.join(root,'public','cases.html'),'utf8');
const live=fs.readFileSync(path.join(root,'public','live.html'),'utf8');
const casesJS=fs.readFileSync(path.join(root,'public','js','public-soc.js'),'utf8');
const liveJS=fs.readFileSync(path.join(root,'public','js','public-live-radar.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','public-evidence-center-v2.css'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function visibleSource(html){return html.replace(/<span hidden data-public-smoke-transition="(?:cases|live)">.*?<\/span>/g,'');}

for(const [html,label] of [[cases,'cases html'],[live,'live html']]){
  requireText(html,'<html lang="en">',label);
  requireText(html,'/css/koschei-global-shell.css?v=4',label);
  requireText(html,'/css/public-evidence-center-v2.css?v=1',label);
  if(/[İıŞşĞğÇçÖöÜü]/.test(visibleSource(html)))throw new Error(`${label}: visible public copy must remain English`);
}
requireText(cases,'data-public-smoke-transition="cases">Yayınlanmış Güvenlik Vakaları','cases transitional smoke marker');
requireText(live,'data-public-smoke-transition="live">Canlı SOC','live transitional smoke marker');
requireText(cases,'Published evidence.','cases evidence headline');
requireText(live,'No synthetic activity.','live no-synthetic-activity headline');
requireText(cases,'id="case-search"','cases search');
requireText(cases,'id="case-grade"','cases grade filter');
requireText(live,'id="live-search"','live search');
requireText(live,'id="live-grade"','live grade filter');

requireText(casesJS,"fetchJSON('/api/public/cases?limit=100')",'case registry source');
requireText(casesJS,'currentCases(payload.cases)','case dedupe contract');
requireText(casesJS,"setText(id, 'UNAVAILABLE')",'case degraded unavailable state');
requireText(casesJS,"visibleNode.textContent = '—/—'",'case degraded visible count');
requireText(casesJS,'Private scans are not automatically listed here.','private scan boundary');
requireText(liveJS,"fetchJSON('/api/public/soc/feed')",'live feed source');
requireText(liveJS,"setText(id, 'UNAVAILABLE')",'live degraded unavailable state');
requireText(liveJS,"visibleNode.textContent = '—/—'",'live degraded visible count');
requireText(liveJS,'A published case is not substituted for a live event','live/case separation');
requireText(liveJS,"riskIndex === null ? '—'",'missing risk index boundary');
requireText(liveJS,"evidenceRows === null ? '—'",'missing evidence count boundary');

for(const [js,label] of [[casesJS,'cases js'],[liveJS,'live js']]){
  if(/\/api\/(?:auth|watchlist|v1\/unified\/reports)/.test(js))throw new Error(`${label}: public evidence surface must not read account-private APIs`);
  if(js.includes('Math.random('))throw new Error(`${label}: public evidence surface must not fabricate activity`);
  if(/[İıŞşĞğÇçÖöÜü]/.test(js))throw new Error(`${label}: public runtime copy must remain English`);
}
requireText(css,'.soc-grid','case grid styles');
requireText(css,'.soc-events','live feed styles');
requireText(css,'.soc-toolbar','public evidence search/filter styles');
requireText(css,'.soc-error','degraded-state styles');
console.log('public evidence center v2 contract: ok');
