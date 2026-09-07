'use strict';
const fs=require('node:fs');
const path=require('node:path');
const root=path.resolve(__dirname,'..');
const safeHTML=fs.readFileSync(path.join(root,'public','safe-check.html'),'utf8');
const txHTML=fs.readFileSync(path.join(root,'public','transaction-shield.html'),'utf8');
const safeJS=fs.readFileSync(path.join(root,'public','js','public-safe-check-v2.js'),'utf8');
const txJS=fs.readFileSync(path.join(root,'public','js','public-transaction-shield-v2.js'),'utf8');
const css=fs.readFileSync(path.join(root,'public','css','koschei.css'),'utf8');

function requireText(source,needle,label){if(!source.includes(needle))throw new Error(`${label}: missing ${needle}`);}
function forbid(source,pattern,label){if(pattern.test(source))throw new Error(`${label}: forbidden pattern ${pattern}`);}

for(const [html,label,script] of [[safeHTML,'safe check html','/js/public-safe-check-v2.js?v=1'],[txHTML,'transaction shield html','/js/public-transaction-shield-v2.js?v=1']]){
  requireText(html,'<html lang="en">',label);
  requireText(html,'/css/koschei.css?v=1',`${label} global shell`);
  requireText(html,'/css/koschei.css?v=1',`${label} shared safety css`);
  requireText(html,script,`${label} v2 controller`);
  requireText(html,'Missing',`${label} explicit missing-evidence copy`);
  forbid(html,/\son[a-z]+\s*=/i,`${label} inline event handler`);
  forbid(html,/<script(?![^>]*\bsrc=)[^>]*>/i,`${label} inline script`);
}
requireText(safeHTML,'id="safeForm"','safe check form');
requireText(safeHTML,'id="out" aria-live="polite"','safe check accessible result');
requireText(safeHTML,'/scan?mode=deep','safe check canonical deep scan');
if(safeHTML.includes('/security-radar'))throw new Error('safe check must not revive duplicate security-radar navigation');
requireText(txHTML,'id="txForm"','transaction shield form');
requireText(txHTML,'No transaction send','transaction shield no-send boundary');

requireText(safeJS,"fetchJSON('/api/arvis/preflight'",'safe check endpoint');
requireText(safeJS,"return decision==='allow'&&(score===null||level!=='low'||limited)?'withhold':decision",'safe check incomplete allow downgrade');
requireText(safeJS,"score===null?'—':score",'safe check missing risk display');
requireText(safeJS,"?'withhold':decision",'safe check fail-closed decision');
requireText(safeJS,'Do not interpret this failure as zero risk or permission to proceed.','safe check degraded boundary');
requireText(safeJS,"form?.addEventListener('submit'",'safe check controller submission');

requireText(txJS,"fetchJSON('/api/public/transaction-simulate'",'transaction simulation endpoint');
requireText(txJS,"return action==='allow'&&(risk===null||level!=='low')?'withhold':action",'transaction incomplete allow downgrade');
requireText(txJS,"risk===null?'—':risk",'transaction missing risk display');
requireText(txJS,"units===null?'UNAVAILABLE'",'transaction missing units display');
requireText(txJS,"Array.isArray(data?.program_ids)?String(data.program_ids.length):'UNAVAILABLE'",'transaction missing programs display');
requireText(txJS,'No zero-risk, zero-program, or permission-to-sign result is produced','transaction degraded boundary');

for(const [js,label] of [[safeJS,'safe check js'],[txJS,'transaction shield js']]){
  requireText(js,"value===null||value===undefined||String(value).trim()===''",`${label} null numeric guard`);
  forbid(js,/Math\.random\s*\(/,`${label} synthetic activity`);
  forbid(js,/\.innerHTML\s*=/,`${label} API-derived innerHTML`);
  forbid(js,/\b(?:signTransaction|signAllTransactions|signAndSendTransaction|sendTransaction)\b/,`${label} transaction authority`);
  forbid(js,/\b(?:localStorage|sessionStorage)\.(?:setItem|removeItem)\s*\(/,`${label} invented session storage`);
  forbid(js,/(?:risk_index|score)\s*\|\|\s*0/,`${label} missing-risk zero fallback`);
  forbid(js,/(?:risk_index|score)\s*\?\?\s*0/,`${label} missing-risk zero fallback`);
}

requireText(css,'.safety-grid','shared safety grid');
requireText(css,'.safety-score.good','explicit good state');
requireText(css,'.safety-score.warn','explicit warning state');
requireText(css,'.safety-score.bad','explicit bad state');
requireText(css,'.safety-error','degraded state styling');
requireText(css,'@media(max-width:620px)','mobile safety layout');
console.log('public safety surfaces v2 contract: ok');
