(()=>{
'use strict';
const REQUEST_TIMEOUT_MS=15000;
const $=id=>document.getElementById(id);
const form=$('safeForm'),run=$('run'),target=$('target'),intent=$('intent'),out=$('out');

function el(tag,className,text){const node=document.createElement(tag);if(className)node.className=className;if(text!==undefined)node.textContent=String(text);return node;}
function numeric(value){if(value===null||value===undefined||String(value).trim()==='')return null;const parsed=Number(value);return Number.isFinite(parsed)?parsed:null;}
function decisionOf(data){const value=String(data?.decision||data?.policy||'').trim().toLowerCase();return ['allow','warn','review','block','withhold'].includes(value)?value:'withhold';}
function levelOf(data){const value=String(data?.risk_level||'').trim().toLowerCase();return ['low','medium','high','critical'].includes(value)?value:'unknown';}
function displayDecision(decision,score,level,limited){return decision==='allow'&&(score===null||level!=='low'||limited)?'withhold':decision;}
function decisionLabel(value){return({allow:'PREFLIGHT CLEAR',warn:'WARNING',review:'REVIEW',block:'BLOCK',withhold:'WITHHOLD'})[value]||'WITHHOLD';}
function tone(score,level,decision){if(decision==='block'||level==='critical'||level==='high'||(score!==null&&score>=75))return'bad';if(decision==='allow')return'good';return'warn';}
function deepScanLink(value){return`/scan?mode=deep&target=${encodeURIComponent(String(value||'').trim())}`;}
function listSection(title,items){const wrap=el('div','safety-section');wrap.append(el('h3','',title));const list=el('ul');for(const value of items){list.append(el('li','',value));}wrap.append(list);return wrap;}
function upgrade(rawTarget,missing){const box=el('div','safety-upgrade');box.append(el('b','','Safe Check is only the rapid preflight layer.'));box.append(el('p','','Open Deep Scan for creator/deployer evidence, owner-normalized holders, liquidity control, Token-2022 extensions, threat pathways, graph relations, and complete evidence explanations.'));if(missing.length)box.append(el('p','safety-fine',`Not checked: ${missing.join(' · ')}`));const link=el('a','safety-btn','Open Deep Scan →');link.href=deepScanLink(rawTarget);box.append(link);return box;}
function render(data,rawTarget){
  const score=numeric(data?.score??data?.risk_index),rawDecision=decisionOf(data),level=levelOf(data),limited=Boolean(data?.coverage_warning),decision=displayDecision(rawDecision,score,level,limited),kind=tone(score,level,decision);
  const scoreBox=el('div',`safety-score ${kind}`);scoreBox.append(el('strong','',decisionLabel(decision)));scoreBox.append(el('small','',`Rapid preflight · ${score===null?'—':score}/100`));
  const nodes=[scoreBox,el('div','safety-decision',`${decisionLabel(decision)} · ${level.toUpperCase()}`),el('p','safety-summary',data?.human_message||data?.verdict||'ARVIS preflight completed; narrative unavailable.')];
  if(decision==='withhold')nodes.push(el('div','safety-warning',rawDecision==='allow'?'Preflight permission was withheld because the response did not contain the complete low-risk evidence required for a clear display.':'Decision authority was not present in the response. This result is withheld rather than treated as safe.'));
  if(limited)nodes.push(el('div','safety-warning',String(data.coverage_warning||'Coverage is incomplete.')));
  const reasons=Array.isArray(data?.reasons)?data.reasons.filter(Boolean).map(String):[];
  const steps=Array.isArray(data?.next_steps)?data.next_steps.filter(Boolean).map(String):[];
  if(reasons.length)nodes.push(listSection('Observed preflight signals',reasons.slice(0,8)));
  if(steps.length)nodes.push(listSection('Recommended next steps',steps.slice(0,8)));
  if(!reasons.length&&!steps.length)nodes.push(el('div','safety-item','No additional preflight signal was returned. Absence of a list is not proof of safety.'));
  const missing=Array.isArray(data?.not_checked)?data.not_checked.filter(Boolean).map(String):[];
  nodes.push(upgrade(rawTarget,missing));
  out.replaceChildren(...nodes);
}
async function fetchJSON(url,options={}){const controller=new AbortController();const timer=setTimeout(()=>controller.abort('koschei_api_timeout'),REQUEST_TIMEOUT_MS);try{const response=await fetch(url,{...options,signal:controller.signal});const data=await response.json().catch(()=>({}));if(!response.ok)throw new Error(data?.error||data?.message||`HTTP ${response.status}`);return data;}catch(error){if(error?.name==='AbortError')throw new Error(`Safe Check did not respond within ${REQUEST_TIMEOUT_MS/1000} seconds.`);throw error;}finally{clearTimeout(timer);}}
form?.addEventListener('submit',async event=>{
  event.preventDefault();const value=String(target?.value||'').trim();if(!value){out.replaceChildren(el('div','safety-warning','Enter a target before running Safe Check.'));target?.focus();return;}
  run.disabled=true;run.textContent='Checking…';const loading=el('div','safety-score');loading.append(el('strong','','…'));loading.append(el('small','','ARVIS deterministic preflight'));out.replaceChildren(loading);
  try{const data=await fetchJSON('/api/arvis/preflight',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:value,intent:intent?.value||'research',note:'public_safe_check'})});render(data,value);}catch(error){const box=el('div','safety-error');box.append(el('b','','DEGRADED DEPENDENCY — no preflight result'));box.append(el('p','',String(error?.message||'Safe Check is unavailable.')));box.append(el('p','','Do not interpret this failure as zero risk or permission to proceed.'));out.replaceChildren(box);}finally{run.disabled=false;run.textContent='Run Safe Check';}
});
})();
