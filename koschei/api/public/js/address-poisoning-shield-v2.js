(()=>{
'use strict';
const $=id=>document.getElementById(id);
const form=$('recipientForm'),out=$('recipientResult'),notice=$('recipientNotice'),run=$('recipientRun');

function el(tag,className,text){const node=document.createElement(tag);if(className)node.className=className;if(text!==undefined)node.textContent=String(text);return node;}
function numeric(value){if(value===null||value===undefined||String(value).trim()==='')return null;const parsed=Number(value);return Number.isFinite(parsed)?parsed:null;}
function policyOf(value){value=String(value||'').trim().toLowerCase();return ['allow','warn','block','withhold'].includes(value)?value:'withhold';}
function levelOf(value){value=String(value||'').trim().toLowerCase();return ['low','medium','high','critical'].includes(value)?value:'unknown';}
function rpcState(value){if(!value||typeof value!=='object')return'unavailable';return value.collected===true?'collected':'limited';}
function guidance(rawPolicy,risk,level,rpc){if(rawPolicy==='block')return{key:'block',label:'DO NOT SEND'};if(rawPolicy==='warn')return{key:'warn',label:'VERIFY FULL ADDRESS'};if(rawPolicy==='allow'&&risk!==null&&level==='low'&&rpc==='collected')return{key:'allow',label:'PREFLIGHT CLEAR'};if(rawPolicy==='allow')return{key:'warn',label:'VERIFY FULL ADDRESS'};return{key:'withhold',label:'WITHHOLD'};}
function tone(key){return key==='allow'?'good':key==='block'?'bad':'warn';}
function contacts(){return String($('contacts')?.value||'').split(/\s+/).map(value=>value.trim()).filter(Boolean).filter((value,index,array)=>array.indexOf(value)===index).slice(0,40);}
function showNotice(message,toneName='warn'){if(!notice)return;notice.textContent=message;notice.className=`safety-warning recipient-notice ${toneName}`;notice.hidden=false;}
function clearNotice(){if(!notice)return;notice.textContent='';notice.hidden=true;notice.className='safety-warning recipient-notice';}
function metric(label,value){const box=el('div','safety-stat');box.append(el('span','',label),el('strong','',value));return box;}
function renderMatches(matches,rpc){const section=el('div','safety-section');section.append(el('h3','','Lookalike evidence'));const list=el('ul','recipient-matches');if(!Array.isArray(matches)){list.append(el('li','','Match evidence was not returned by the service.'));}else if(!matches.length){list.append(el('li','',rpc==='collected'?'No lookalike match was returned in the evaluated contact scope.':'No lookalike match was returned in the available contact scope; RPC coverage is limited.'));}else{for(const item of matches.slice(0,20)){const signal=String(item?.signal||'lookalike signal'),known=String(item?.known_address||'address unavailable'),bonus=numeric(item?.risk_bonus);list.append(el('li','',`${signal} · ${known} · risk bonus ${bonus===null?'—':`+${bonus}`}`));}}section.append(list);return section;}
function renderEvidencePolicy(policy){const section=el('div','safety-section');section.append(el('h3','','Evidence policy'));if(!policy||typeof policy!=='object'){section.append(el('p','safety-summary','Evidence-policy metadata was not returned.'));return section;}const noEvidence=policy.no_evidence_no_claim===true?'ENFORCED':'UNAVAILABLE';section.append(metric('No evidence / no claim',noEvidence));const blocked=Array.isArray(policy.blocked_terms_without_proof)?policy.blocked_terms_without_proof.filter(Boolean).map(String):[];if(blocked.length)section.append(el('p','safety-fine',`Claims blocked without proof: ${blocked.join(' · ')}`));return section;}
function render(data){
  const risk=numeric(data?.risk_index),level=levelOf(data?.risk_level),rawPolicy=policyOf(data?.policy),rpc=rpcState(data?.rpc_evidence),guide=guidance(rawPolicy,risk,level,rpc),observed=numeric(data?.observed_contact_count);
  const score=el('div',`safety-score ${tone(guide.key)}`);score.append(el('strong','',guide.label),el('small','',`Recipient risk · ${risk===null?'—':risk}/100 · ${level.toUpperCase()}`));
  const policyLine=el('div','safety-decision',`${guide.label} · engine ${rawPolicy.toUpperCase()}`);
  const summary=el('p','safety-summary',data?.verdict||'Recipient-risk evaluation completed; verdict narrative unavailable.');
  const stats=el('div','safety-stats');stats.append(metric('Observed contacts',observed===null?'UNAVAILABLE':String(observed)),metric('RPC contact evidence',rpc.toUpperCase()));
  const nodes=[score,policyLine,summary,stats];
  if(guide.key==='withhold')nodes.push(el('div','safety-warning','Decision authority was not present in the response. Recipient guidance is withheld.'));
  if(rawPolicy==='allow'&&guide.key!=='allow')nodes.push(el('div','safety-warning','Engine policy was ALLOW, but the UI did not display a clear-send state because complete LOW-risk RPC contact evidence was not available. Verify the full address out-of-band.'));
  if(rpc!=='collected')nodes.push(el('div','safety-warning','Recent RPC contact evidence is limited or unavailable. Do not rely on a truncated recipient display.'));
  nodes.push(renderMatches(data?.matches,rpc),renderEvidencePolicy(data?.evidence_policy));
  const candidate=String(data?.candidate||'').trim();if(candidate){const section=el('div','safety-section');section.append(el('h3','','Candidate recipient'),el('p','safety-mono',candidate));nodes.push(section);}
  const boundary=el('div','safety-boundary');boundary.append(el('b','','Read-only boundary: '),document.createTextNode(String(data?.disclaimer||'This analysis does not sign, send, or authorize a transaction.')));nodes.push(boundary);
  out.replaceChildren(...nodes);
}
async function callAPI(body){const response=await KoscheiAuth.apiCall('/api/v1/address-poisoning/check',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});if(!response)throw new Error('Recipient evidence service could not be reached.');const data=await response.json().catch(()=>({}));if(response.status===401){location.href=KoscheiAuth.loginURL('/login.html');throw new Error('Authentication session expired.');}if(!response.ok||data?.ok!==true)throw new Error(data?.message||data?.error||`Recipient check failed (${response.status}).`);return data;}
async function bootstrap(){
  if(!window.KoscheiAuth){showNotice('Authentication client is unavailable. No recipient decision was inferred.','bad');return;}
  try{await KoscheiAuth.init();}catch(error){showNotice(error?.message||'Authentication initialization failed.','bad');return;}
  if(!KoscheiAuth.requireAuth('/login.html'))return;
  form?.addEventListener('submit',async event=>{
    event.preventDefault();clearNotice();const wallet=String($('wallet')?.value||'').trim(),candidate=String($('candidate')?.value||'').trim();if(!wallet||!candidate){showNotice('Enter both your wallet and the recipient address before running Recipient Shield.');return;}
    run.disabled=true;run.textContent='Checking recipient…';const loading=el('div','safety-score');loading.append(el('strong','','…'),el('small','','Evaluating lookalike and recent-contact evidence'));out.replaceChildren(loading);
    try{render(await callAPI({wallet,candidate,network:'solana-mainnet',known_contacts:contacts()}));}catch(error){const box=el('div','safety-error');box.append(el('b','','DEGRADED DEPENDENCY — no recipient decision'));box.append(el('p','',String(error?.message||'Recipient Shield is unavailable.')));box.append(el('p','','Do not interpret an unavailable check as permission to send. Verify the full recipient address out-of-band.'));out.replaceChildren(box);}finally{run.disabled=false;run.textContent='Check recipient';}
  });
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bootstrap);else bootstrap();
})();
