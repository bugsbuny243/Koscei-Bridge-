(()=>{
'use strict';
const REQUEST_TIMEOUT_MS=30000;
const $=id=>document.getElementById(id);
const form=$('firewallForm'),run=$('runButton'),result=$('firewallResult'),status=$('firewallStatus');

function el(tag,className,text){const node=document.createElement(tag);if(className)node.className=className;if(text!==undefined)node.textContent=String(text);return node;}
function numeric(value){if(value===null||value===undefined||String(value).trim()==='')return null;const parsed=Number(value);return Number.isFinite(parsed)?parsed:null;}
function actionOf(value){value=String(value||'').trim().toLowerCase();return ['allow','warn','block','withhold'].includes(value)?value:'withhold';}
function levelOf(value){value=String(value||'').trim().toLowerCase();return ['low','medium','high','critical'].includes(value)?value:'unknown';}
function displayedAction(raw,risk,level){return raw==='allow'&&(risk===null||level!=='low')?'withhold':raw;}
function label(value){return({allow:'PREFLIGHT CLEAR',warn:'REVIEW BEFORE SIGNING',block:'DO NOT SIGN',withhold:'WITHHOLD'})[value]||'WITHHOLD';}
function tone(value){return value==='allow'?'good':value==='block'?'bad':'warn';}
function showStatus(message,bad=false){status.hidden=false;status.textContent=message;status.className=`firewall-status ${bad?'bad':'good'}`;}
function hideStatus(){status.hidden=true;status.textContent='';status.className='firewall-status';}
function metric(name,value){const box=el('div','safety-stat');box.append(el('span','',name),el('strong','',value));return box;}
function section(title){const node=el('section','firewall-section');node.append(el('h3','',title));return node;}
function renderFindings(items){const wrap=section('Security findings'),list=el('div','firewall-list');if(!Array.isArray(items)){list.append(el('div','firewall-item warn','Findings were not returned by the evidence service.'));}else if(!items.length){list.append(el('div','firewall-item','No finding was returned in the evaluated simulation scope. This is not a safety guarantee.'));}else{for(const item of items.slice(0,30)){const severity=String(item?.severity||'unknown').toLowerCase();const card=el('div',`firewall-item ${['critical','high'].includes(severity)?'bad':severity==='medium'?'warn':''}`);card.append(el('span','firewall-severity',severity.toUpperCase()),el('b','',item?.title||item?.code||'Finding'),el('p','',item?.evidence||'Evidence detail unavailable.'));list.append(card);}}wrap.append(list);return wrap;}
function renderLines(title,items,emptyText,missingText){const wrap=section(title),box=el('pre','firewall-code');if(!Array.isArray(items))box.textContent=missingText;else if(!items.length)box.textContent=emptyText;else box.textContent=items.slice(0,120).map(value=>String(value??'')).join('\n');wrap.append(box);return wrap;}
function render(data,responseOK){
  const risk=numeric(data?.risk_index),level=levelOf(data?.risk_level),raw=actionOf(data?.action),action=displayedAction(raw,risk,level),units=numeric(data?.simulation?.units_consumed),latency=numeric(data?.latency_ms),programs=Array.isArray(data?.program_ids)?data.program_ids:null,logs=Array.isArray(data?.simulation?.logs)?data.simulation.logs:null;
  const top=el('div',`safety-score ${tone(action)}`);top.append(el('strong','',label(action)),el('small','',`Transaction risk · ${risk===null?'—':risk}/100 · ${level.toUpperCase()}`));
  const nodes=[top,el('div','safety-decision',`${label(action)} · engine ${raw.toUpperCase()}`),el('p','safety-summary',data?.summary||data?.verdict||'Transaction Guard completed; narrative unavailable.')];
  if(action==='withhold')nodes.push(el('div','safety-warning',raw==='allow'?'Engine action was ALLOW, but clear signing guidance was withheld because complete LOW-risk evidence was not present.':'Required decision evidence is incomplete or unavailable. Signing guidance is withheld.'));
  if(!responseOK)nodes.push(el('div','safety-warning','The endpoint returned a degraded/non-success response. The engine result is shown only as evidence; it is not permission to sign.'));
  const stats=el('div','safety-stats');stats.append(metric('Request ID',String(data?.request_id||'UNAVAILABLE')),metric('Compute units',units===null?'UNAVAILABLE':units.toLocaleString('en-US')),metric('Programs',programs===null?'UNAVAILABLE':String(programs.length)),metric('Latency',latency===null?'UNAVAILABLE':`${latency} ms`));nodes.push(stats);
  nodes.push(renderFindings(data?.findings));
  nodes.push(renderLines('Called programs',programs,'No program id was returned in the evaluated simulation scope.','Called-program evidence is unavailable.'));
  nodes.push(renderLines('Sanitized simulation logs',logs,'No simulation log was returned in the evaluated simulation scope.','Simulation-log evidence is unavailable.'));
  if(data?.transaction_fingerprint){const fp=section('Transaction fingerprint');fp.append(el('p','safety-mono',data.transaction_fingerprint));nodes.push(fp);}
  const boundary=el('div','safety-boundary');boundary.append(el('b','','Shadow-mode boundary: '),document.createTextNode('Koschei does not sign, submit, store, or automatically block this transaction. The serialized transaction and API key stay outside browser persistence in this UI.'));nodes.push(boundary);
  result.replaceChildren(...nodes);
}
async function request(body,key){const controller=new AbortController();const timer=setTimeout(()=>controller.abort('koschei_firewall_timeout'),REQUEST_TIMEOUT_MS);try{const response=await fetch('/api/v1/shield/transaction',{method:'POST',headers:{'Content-Type':'application/json','X-API-Key':key},body:JSON.stringify(body),signal:controller.signal});const data=await response.json().catch(()=>({}));if(!response.ok&&actionOf(data?.action)!=='withhold'&&actionOf(data?.action)!=='block')throw new Error(data?.message||data?.error||`Transaction Guard failed (${response.status}).`);return{data,responseOK:response.ok};}catch(error){if(error?.name==='AbortError')throw new Error(`Transaction Guard did not respond within ${REQUEST_TIMEOUT_MS/1000} seconds.`);throw error;}finally{clearTimeout(timer);}}
form?.addEventListener('submit',async event=>{
  event.preventDefault();hideStatus();const key=String($('apiKey')?.value||'').trim(),transaction=String($('transaction')?.value||'').trim();if(!key){showStatus('Enter a Koschei API key. It is kept only in this page memory and is not persisted.',true);$('apiKey')?.focus();return;}if(!transaction){showStatus('Enter the base64 serialized transaction before simulation.',true);$('transaction')?.focus();return;}
  run.disabled=true;run.textContent='Running shadow simulation…';const loading=el('div','safety-score');loading.append(el('strong','','…'),el('small','','Evidence-first Transaction Guard'));result.replaceChildren(loading);
  try{const {data,responseOK}=await request({transaction,encoding:$('encoding')?.value||'base64',network:$('network')?.value||'solana-mainnet',wallet:String($('wallet')?.value||'').trim()},key);render(data,responseOK);showStatus(responseOK?'Simulation completed. Review the evidence before signing.':'Decision evidence returned in degraded mode. Review the WITHHOLD/BLOCK result.',!responseOK);}catch(error){const box=el('div','safety-error');box.append(el('b','','DEGRADED DEPENDENCY — no signing guidance'));box.append(el('p','',String(error?.message||'Transaction Guard is unavailable.')));box.append(el('p','','Do not interpret a failed request as zero risk or permission to sign.'));result.replaceChildren(box);showStatus('No usable transaction decision was produced.',true);}finally{run.disabled=false;run.textContent='Simulate transaction';}
});
})();
