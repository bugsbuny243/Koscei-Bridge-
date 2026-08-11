(()=>{
'use strict';
const REQUEST_TIMEOUT_MS=15000;
const $=id=>document.getElementById(id);
const run=$('run'),target=$('target'),intent=$('intent'),result=$('result');

function el(tag,className,text){const node=document.createElement(tag);if(className)node.className=className;if(text!==undefined)node.textContent=String(text);return node;}
function numeric(value){if(value===null||value===undefined||String(value).trim()==='')return null;const parsed=Number(value);return Number.isFinite(parsed)?parsed:null;}
function decisionOf(data){const value=String(data?.decision||data?.policy||'').trim().toLowerCase();return ['allow','warn','review','block','withhold'].includes(value)?value:'withhold';}
function levelOf(data){const value=String(data?.risk_level||'').trim().toLowerCase();return ['low','medium','high','critical'].includes(value)?value:'unknown';}
function displayedDecision(raw,score,level,limited){return raw==='allow'&&(score===null||level!=='low'||limited)?'withhold':raw;}
function decisionLabel(value){return({allow:'PREFLIGHT CLEAR',warn:'WARNING',review:'REVIEW',block:'BLOCK',withhold:'WITHHOLD'})[value]||'WITHHOLD';}
function tone(value,score,level){if(value==='block'||level==='critical'||level==='high'||(score!==null&&score>=75))return'bad';if(value==='allow')return'good';return'warn';}
function line(text,className='line'){return el('div',className,text);}
function deepScanURL(value){return`/scan?mode=deep&target=${encodeURIComponent(String(value||'').trim())}`;}
function showResult(nodes){result.className='result show';result.replaceChildren(...nodes);}
function renderPreflight(data){
  const score=numeric(data?.score??data?.risk_index),level=levelOf(data),raw=decisionOf(data),limited=Boolean(data?.coverage_warning),decision=displayedDecision(raw,score,level,limited);
  const scoreNode=el('div',`score ${tone(decision,score,level)}`,score===null?'—':score);scoreNode.append(el('small','homepage-score-label','PREFLIGHT / 100'));
  const heading=el('b','',`${decisionLabel(decision)} · ${level.toUpperCase()}`);
  const summary=el('p','sub',data?.human_message||data?.verdict||'ARVIS preflight completed; narrative unavailable.');
  const nodes=[scoreNode,heading,summary];
  if(decision==='withhold')nodes.push(line(raw==='allow'?'Preflight permission was withheld because the response did not contain the complete LOW-risk evidence required for a clear display.':'Decision authority was unavailable. This preflight is withheld rather than treated as safe.'));
  if(limited)nodes.push(line(`EVIDENCE BOUNDARY · ${String(data.coverage_warning||'Coverage is incomplete.')}`));
  const missing=Array.isArray(data?.not_checked)?data.not_checked.filter(Boolean).map(String):[];
  if(missing.length)nodes.push(line(`Not checked: ${missing.join(' · ')}`));
  const reasons=Array.isArray(data?.reasons)?data.reasons.filter(Boolean).map(String):[];
  const steps=Array.isArray(data?.next_steps)?data.next_steps.filter(Boolean).map(String):[];
  for(const item of reasons.concat(steps).slice(0,5))nodes.push(line(item));
  if(!reasons.length&&!steps.length)nodes.push(line('No additional signal list was returned. Absence of a list is not proof of safety.'));
  const actions=el('div','actions homepage-result-actions');
  const safe=el('a','btn primary','Open Safe Check');safe.href='/safe-check';
  const deep=el('a','btn','Open Deep Scan');deep.href=deepScanURL(target?.value);
  actions.append(safe,deep);nodes.push(actions);showResult(nodes);
}
async function fetchJSON(url,options={}){const controller=new AbortController();const timer=setTimeout(()=>controller.abort('koschei_api_timeout'),REQUEST_TIMEOUT_MS);try{const response=await fetch(url,{...options,signal:controller.signal});const data=await response.json().catch(()=>({}));if(!response.ok)throw new Error(data?.error||data?.message||`HTTP ${response.status}`);return data;}catch(error){if(error?.name==='AbortError')throw new Error(`ARVIS did not respond within ${REQUEST_TIMEOUT_MS/1000} seconds.`);throw error;}finally{clearTimeout(timer);}}
run?.addEventListener('click',async()=>{
  const value=String(target?.value||'').trim();if(!value){showResult([line('Enter a URL, token, wallet, recipient, program, or signature request first.')]);target?.focus();return;}
  run.disabled=true;run.textContent='Checking…';showResult([line('ARVIS is collecting deterministic preflight evidence…')]);
  try{renderPreflight(await fetchJSON('/api/arvis/preflight',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:value,intent:intent?.value||'research',note:'landing_instant_safe_check'})}));}
  catch(error){const box=el('div','line homepage-degraded',`DEGRADED DEPENDENCY — ${String(error?.message||'Preflight unavailable.') } Do not interpret this failure as zero risk or permission to proceed.`);const actions=el('div','actions homepage-result-actions');const retry=el('a','btn primary','Open Safe Check');retry.href='/safe-check';const deep=el('a','btn','Open Deep Scan');deep.href=deepScanURL(value);actions.append(retry,deep);showResult([box,actions]);}
  finally{run.disabled=false;run.textContent='Check with ARVIS';}
});

function metric(id,value){const node=$(id);if(!node)return;const parsed=numeric(value);node.textContent=parsed===null?'—':parsed.toLocaleString('en-US');}
async function loadHealth(){
  try{
    const response=await fetch('/health',{cache:'no-store'});const data=await response.json().catch(()=>({}));if(!response.ok)throw new Error(`HTTP ${response.status}`);
    const arvis=data?.arvis&&typeof data.arvis==='object'?data.arvis:null,failures=arvis?.failures&&typeof arvis.failures==='object'?arvis.failures:null;
    metric('completed',arvis?.processing_completed);
    metric('verdicts',arvis?.signed_verdicts_total??arvis?.visible_verdicts);
    metric('retryable',failures?.retryable);
    metric('exhausted',failures?.exhausted);
  }catch{
    for(const id of ['completed','verdicts','retryable','exhausted']){const node=$(id);if(node)node.textContent='—';}
  }
}
loadHealth();
})();
