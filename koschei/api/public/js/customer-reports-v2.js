(()=>{
'use strict';
if(window.__koscheiCustomerReportsV2)return;
window.__koscheiCustomerReportsV2=true;

const $=id=>document.getElementById(id);
const text=value=>String(value??'').trim();
const lower=value=>text(value).toLowerCase();
const hasValue=value=>value!==null&&value!==undefined&&String(value).trim()!=='';
const isObject=value=>Boolean(value)&&typeof value==='object'&&!Array.isArray(value);
const allowedStates=new Set(['queued','running','completed','failed']);
let history=null;

function node(tag,className,value){const el=document.createElement(tag);if(className)el.className=className;if(value!==undefined)el.textContent=String(value);return el;}
function clear(host){while(host?.firstChild)host.removeChild(host.firstChild);}
function strictDate(value){if(!hasValue(value))return null;const date=new Date(value);return Number.isNaN(date.getTime())?null:date;}
function when(value){const date=strictDate(value);return date?new Intl.DateTimeFormat('en-US',{dateStyle:'medium',timeStyle:'short'}).format(date):'UNAVAILABLE';}
function integerOrNull(value,min=0,max=Number.MAX_SAFE_INTEGER){if(value===null||value===undefined||value==='')return null;const parsed=Number(value);return Number.isInteger(parsed)&&parsed>=min&&parsed<=max?parsed:null;}
function validState(value){const state=lower(value);return allowedStates.has(state)?state:'unknown';}
function status(message,tone=''){const host=$('reportStatus');if(!host)return;host.textContent=message;host.className=`ops-status show${tone?` ${tone}`:''}`;}
function clearStatus(){const host=$('reportStatus');if(host){host.textContent='';host.className='ops-status';}}
function setKPI(id,value,detail,tone=''){const host=$(id);if(!host)return;host.dataset.tone=tone;host.querySelector('strong').textContent=value;host.querySelector('small').textContent=detail;}
function setUnavailableKPIs(detail){setKPI('reportTotalKpi','—',detail,'bad');setKPI('reportCompletedKpi','—',detail,'bad');setKPI('reportSignedKpi','—',detail,'bad');setKPI('reportLatestKpi','—',detail,'bad');const count=$('reportVisibleCount');if(count)count.textContent='—/—';}

function resultOf(item){return item?.result_available===true&&isObject(item?.result)?item.result:null;}
function decisionOf(item){const result=resultOf(item);if(!result)return null;const summary=isObject(result.analysis_summary)?result.analysis_summary:null;if(summary&&isObject(summary.decision))return summary.decision;if(isObject(result.final_verdict))return result.final_verdict;return null;}
function signatureState(item){
  if(validState(item?.status)!=='completed')return {kind:'not_applicable',label:'NOT COMPLETED'};
  if(item?.result_available!==true||!isObject(item?.result))return {kind:'unavailable',label:'RESULT UNAVAILABLE'};
  const decision=decisionOf(item);if(!decision)return {kind:'unavailable',label:'VERDICT UNAVAILABLE'};
  const signed=typeof decision.signed==='boolean'?decision.signed:null,signature=text(decision.signature),ruleset=text(decision.ruleset_version);
  if(signed===true&&signature&&ruleset)return {kind:'signed',label:'SIGNED',signature,ruleset};
  if(signed===false)return {kind:'unsigned',label:'UNSIGNED'};
  if(signed===true)return {kind:'incomplete',label:'SIGNATURE INCOMPLETE'};
  return {kind:'unavailable',label:'SIGNATURE UNAVAILABLE'};
}
function decisionLabel(item,key){const decision=decisionOf(item);return decision&&hasValue(decision[key])?String(decision[key]).trim():'UNAVAILABLE';}
function toneForState(state){if(state==='completed')return'low';if(state==='failed')return'critical';if(state==='running')return'medium';if(state==='queued')return'info';return'unknown';}
function scanURL(target){return`/scan?mode=deep&target=${encodeURIComponent(target)}`;}
function metric(label,value){const wrap=node('div');wrap.append(node('label','',label),node('strong','',value));return wrap;}
function actionLink(label,href,primary=false){const link=node('a',`ops-btn${primary?' primary':''}`,label);link.href=href;return link;}

function updateKPIs(items){
  if(!Array.isArray(items)){setUnavailableKPIs('Canonical investigation history unavailable; no history count inferred.');return;}
  const states=items.map(item=>validState(item?.status));
  const completed=states.filter(state=>state==='completed').length;
  const signed=items.filter(item=>signatureState(item).kind==='signed').length;
  const latest=items.find(item=>strictDate(item?.queued_at));
  const hasUnknown=states.includes('unknown');
  setKPI('reportTotalKpi',String(items.length),items.length?'Account-scoped canonical jobs returned by the durable store.':'No canonical investigation job is retained for this account.',items.length?'good':'');
  setKPI('reportCompletedKpi',String(completed),hasUnknown?'Completed count shown, but at least one job has an unknown state.':completed?'Jobs explicitly marked completed.':'No job explicitly marked completed.',hasUnknown?'warn':completed?'good':'');
  setKPI('reportSignedKpi',String(signed),signed?'Completed results meeting the strict signed + signature + ruleset gate.':'No completed result meets the strict signature gate.',signed?'good':'');
  setKPI('reportLatestKpi',latest?when(latest.queued_at):'—',latest?'Newest valid queued timestamp in server order.':'No valid queued timestamp returned.',latest?'good':'');
}

function matches(item,query,stateFilter){
  const state=validState(item?.status),decision=decisionOf(item),haystack=lower(`${item?.id||''} ${item?.target||''} ${item?.network||''} ${state} ${decision?.verdict||''} ${decision?.grade||''}`);
  return(!stateFilter||state===stateFilter)&&(!query||haystack.includes(query));
}

function render(){
  const host=$('reportList');if(!host)return;clear(host);
  if(!Array.isArray(history)){host.append(node('div','ops-empty','Canonical investigation history is unavailable. Missing collection evidence is not treated as an empty vault.'));$('reportVisibleCount').textContent='—/—';return;}
  const query=lower($('reportSearch')?.value),stateFilter=lower($('reportStateFilter')?.value),filtered=history.filter(item=>matches(item,query,stateFilter));
  $('reportVisibleCount').textContent=`${filtered.length}/${history.length}`;
  if(filtered.length===0){host.append(node('div','ops-empty',history.length?'No canonical investigation matches the current filters.':'No canonical investigation history is retained for this account.'));return;}

  for(const item of filtered){
    const state=validState(item?.status),target=text(item?.target),network=text(item?.network),id=text(item?.id),progress=integerOrNull(item?.progress,0,100),attempts=integerOrNull(item?.attempts,0),signature=signatureState(item),verdict=decisionLabel(item,'verdict'),grade=decisionLabel(item,'grade');
    const card=node('article','ops-record');
    const head=node('div','ops-record-head'),title=node('div','ops-record-title');
    title.append(node('span','',id?`JOB ${id}`:'JOB ID UNAVAILABLE'),node('b','',target||'Target unavailable'),node('small','',`Queued ${when(item?.queued_at)} · Updated ${when(item?.updated_at)}`));
    head.append(title,node('span',`ops-risk ${toneForState(state)}`,state==='unknown'?'UNAVAILABLE':state.toUpperCase()));
    const metadata=node('div','ops-record-meta');
    metadata.append(metric('Progress',progress===null?'UNAVAILABLE':`${progress}%`),metric('Attempts',attempts===null?'UNAVAILABLE':attempts),metric('Verdict',verdict),metric('Grade',grade),metric('Evidence state',signature.label),metric('Network',network||'UNAVAILABLE'));
    card.append(head,metadata);
    if(state==='failed'){const error=text(item?.error_message)||text(item?.error_code)||'Failure details unavailable.';card.append(node('p','ops-record-copy',error));}
    if(state==='completed'&&item?.result_available!==true)card.append(node('p','ops-record-copy','Job is marked completed but result payload is unavailable. No verdict or signature state is inferred.'));
    const actions=node('div','ops-record-actions');
    if(target){actions.append(actionLink('Re-investigate',scanURL(target),true));const copy=node('button','ops-btn','Copy target');copy.type='button';copy.dataset.copyTarget=target;actions.append(copy);}
    if(actions.childNodes.length)card.append(actions);
    host.append(card);
  }
}

function historyAccessError(statusCode){
  if(statusCode===401)return'Sign in to view your investigation history.';
  if(statusCode===402||statusCode===403)return'Investigation history requires an active Starter plan or higher.';
  if(statusCode===429)return'Investigation history is temporarily rate limited. Try again shortly.';
  return'Investigation history is unavailable right now. No history state was inferred.';
}

async function api(){
  const response=await KoscheiAuth.apiCall('/api/v1/radar/jobs/',{method:'GET'});
  const raw=await response.text();let data={};
  if(raw){try{data=JSON.parse(raw);}catch{throw new Error('Investigation history returned invalid JSON.');}}
  if(!response.ok)throw new Error(historyAccessError(response.status));
  return data;
}

async function load(){
  try{await KoscheiAuth.init();}catch{}
  if(!KoscheiAuth.requireAuth('/login.html'))return;
  clearStatus();
  try{
    const data=await api();
    if(data?.ok!==true||data?.schema_version!=='koschei-customer-investigation-history-v1'||data?.source!=='web3_jobs'||data?.job_type!=='canonical_investigation'||!Array.isArray(data?.history)){
      history=null;updateKPIs(history);render();status('Investigation history response is structurally incomplete. No empty history or signed evidence state was inferred.','bad');return;
    }
    history=data.history;updateKPIs(history);render();
  }catch(error){history=null;updateKPIs(history);render();status(error.message||'Investigation history is unavailable.','bad');}
}

async function copyTarget(value,button){try{await navigator.clipboard.writeText(value);const previous=button.textContent;button.textContent='Copied';window.setTimeout(()=>{button.textContent=previous;},900);}catch{status('Clipboard access is unavailable in this browser.','bad');}}
document.addEventListener('click',event=>{const button=event.target.closest('[data-copy-target]');if(button)copyTarget(button.dataset.copyTarget||'',button);});
$('reportSearch')?.addEventListener('input',render);$('reportStateFilter')?.addEventListener('change',render);$('reportReload')?.addEventListener('click',load);
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',load);else load();
})();
