(()=>{
'use strict';
const REQUEST_TIMEOUT_MS=30000;
const $=id=>document.getElementById(id);
const form=$('txForm'),submit=$('submitTx'),empty=$('empty'),result=$('result');

function el(tag,className,text){const node=document.createElement(tag);if(className)node.className=className;if(text!==undefined)node.textContent=String(text);return node;}
function numeric(value){if(value===null||value===undefined||String(value).trim()==='')return null;const parsed=Number(value);return Number.isFinite(parsed)?parsed:null;}
function actionOf(value){value=String(value||'').trim().toLowerCase();return ['allow','warn','review','block','withhold'].includes(value)?value:'withhold';}
function actionLabel(value){return({allow:'PREFLIGHT CLEAR',warn:'REVIEW BEFORE SIGNING',review:'REVIEW BEFORE SIGNING',block:'DO NOT SIGN',withhold:'WITHHOLD'})[value]||'WITHHOLD';}
function riskLevel(value){value=String(value||'').trim().toLowerCase();return ['low','medium','high','critical'].includes(value)?value:'unknown';}
function tone(action,level){if(action==='block'||level==='critical'||level==='high')return'bad';if(action==='allow'&&level==='low')return'good';return'warn';}
function renderList(id,items,formatter,emptyText,missingText){const node=$(id);node.replaceChildren();if(!Array.isArray(items)){node.append(el('li','',missingText));return;}if(!items.length){node.append(el('li','',emptyText));return;}for(const item of items){node.append(el('li','',formatter?formatter(item):String(item??'')));}}
async function fetchJSON(url,options={}){const controller=new AbortController();const timer=setTimeout(()=>controller.abort('koschei_api_timeout'),REQUEST_TIMEOUT_MS);try{const response=await fetch(url,{...options,signal:controller.signal});const data=await response.json().catch(()=>({}));if(!response.ok)throw new Error(data?.message||data?.code||`HTTP ${response.status}`);return data;}catch(error){if(error?.name==='AbortError')throw new Error(`Transaction evidence service did not respond within ${REQUEST_TIMEOUT_MS/1000} seconds.`);throw error;}finally{clearTimeout(timer);}}
function showDegraded(error){result.hidden=true;empty.hidden=false;const box=el('div','safety-error');box.append(el('b','','DEGRADED DEPENDENCY — no simulation result'));box.append(el('p','',String(error?.message||'Solana RPC or evidence service is unavailable.')));box.append(el('p','','No zero-risk, zero-program, or permission-to-sign result is produced when simulation evidence is unavailable.'));empty.replaceChildren(box);}
form?.addEventListener('submit',async event=>{
  event.preventDefault();const transaction=String($('transaction')?.value||'').trim();if(!transaction)return;
  submit.disabled=true;submit.textContent='Running read-only simulation…';result.hidden=true;empty.hidden=false;const loading=el('div','safety-score');loading.append(el('strong','','…'));loading.append(el('small','','Read-only Solana simulation · transaction is not signed or sent'));empty.replaceChildren(loading);
  try{
    const data=await fetchJSON('/api/public/transaction-simulate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({transaction,encoding:'base64',network:'solana-mainnet',wallet:String($('wallet')?.value||'').trim()})});
    const action=actionOf(data?.action),level=riskLevel(data?.risk_level),risk=numeric(data?.risk_index),units=numeric(data?.simulation?.units_consumed);
    empty.hidden=true;result.hidden=false;
    $('action').textContent=actionLabel(action);$('action').className=`safety-chip ${tone(action,level)==='bad'?'warn':''}`;
    $('risk').textContent=`${risk===null?'—':risk}/100`;
    $('summary').textContent=data?.summary||'Simulation completed; narrative unavailable.';
    $('fingerprint').textContent=data?.transaction_fingerprint||'UNAVAILABLE';
    $('units').textContent=units===null?'UNAVAILABLE':units.toLocaleString('en-US');
    $('programCount').textContent=Array.isArray(data?.program_ids)?String(data.program_ids.length):'UNAVAILABLE';
    renderList('findings',data?.findings,item=>`${String(item?.severity||'unknown').toUpperCase()} · ${item?.title||item?.code||'finding'}: ${item?.evidence||'evidence detail unavailable'}`,'No finding was returned in the evaluated simulation scope.','Findings were not returned by the evidence service.');
    renderList('programs',data?.program_ids,null,'No program id was returned in the evaluated simulation scope.','Called-program evidence is unavailable.');
    $('warning').textContent=data?.warning||'Read-only shadow mode. This result does not sign, send, or block the transaction.';
    if(action==='withhold')$('warning').textContent='Decision authority was not present in the response. Signing guidance is withheld.';
  }catch(error){showDegraded(error);}finally{submit.disabled=false;submit.textContent='Simulate transaction';}
});
})();
