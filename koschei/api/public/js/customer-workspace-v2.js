(()=>{
'use strict';
if(window.__koscheiCustomerWorkspaceV2)return;
window.__koscheiCustomerWorkspaceV2=true;

const $=id=>document.getElementById(id);
const arr=value=>Array.isArray(value)?value:[];
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const text=value=>String(value??'').trim();
const lower=value=>text(value).toLowerCase();
const hasValue=value=>value!==null&&value!==undefined&&String(value).trim()!=='';
const isObject=value=>Boolean(value)&&typeof value==='object'&&!Array.isArray(value);
const displayNumber=value=>Number.isFinite(Number(value))?new Intl.NumberFormat('en-US',{maximumFractionDigits:2}).format(Number(value)):'—';
const when=value=>{const parsed=new Date(value||0);return Number.isNaN(parsed.getTime())?'—':new Intl.DateTimeFormat('en-US',{dateStyle:'medium',timeStyle:'short'}).format(parsed);};
const strictWhen=value=>{if(!hasValue(value))return'UNAVAILABLE';const parsed=new Date(value);return Number.isNaN(parsed.getTime())?'UNAVAILABLE':new Intl.DateTimeFormat('en-US',{dateStyle:'medium',timeStyle:'short'}).format(parsed);};
const historyStates=new Set(['queued','running','completed','failed']);

async function read(path){
  try{
    const response=await KoscheiAuth.apiCall(path,{method:'GET'});
    const data=await response.json().catch(()=>({}));
    return {ok:response.ok,status:response.status,data};
  }catch(error){
    return {ok:false,status:0,data:{},error};
  }
}

function setKPI(id,value,detail,tone=''){
  const node=$(id);if(!node)return;
  node.dataset.tone=tone;
  const strong=node.querySelector('strong'),small=node.querySelector('small');
  if(strong)strong.textContent=value;
  if(small)small.textContent=detail;
}

function historyFrom(result){
  const data=result?.data;
  if(!result?.ok||!isObject(data)||data.ok!==true||data.schema_version!=='koschei-customer-investigation-history-v1'||data.source!=='web3_jobs'||data.job_type!=='canonical_investigation'||!Array.isArray(data.history))return null;
  return data.history;
}
function targetsFrom(result){return arr(result?.data?.targets);}
function alertsFrom(result){return arr(result?.data?.alerts);}

function latestBy(items,field){
  return [...items].sort((a,b)=>Date.parse(b?.[field]||0)-Date.parse(a?.[field]||0))[0]||null;
}

function normalizedTone(value){
  const raw=lower(value);
  return ['low','medium','high','critical','warning','info'].includes(raw)?raw:'info';
}
function historyState(value){const state=lower(value);return historyStates.has(state)?state:'unknown';}
function historyResult(item){return item?.result_available===true&&isObject(item?.result)?item.result:null;}
function historyDecision(item){const result=historyResult(item);if(!result)return null;const summary=isObject(result.analysis_summary)?result.analysis_summary:null;if(summary&&isObject(summary.decision))return summary.decision;if(isObject(result.final_verdict))return result.final_verdict;return null;}
function historyEvidenceState(item){
  if(historyState(item?.status)!=='completed')return'NOT COMPLETED';
  const decision=historyDecision(item);if(!decision)return item?.result_available===true?'VERDICT UNAVAILABLE':'RESULT UNAVAILABLE';
  const signed=typeof decision.signed==='boolean'?decision.signed:null,signature=text(decision.signature),ruleset=text(decision.ruleset_version);
  if(signed===true&&signature&&ruleset)return'SIGNED';
  if(signed===false)return'UNSIGNED';
  if(signed===true)return'SIGNATURE INCOMPLETE';
  return'SIGNATURE UNAVAILABLE';
}
function historyDecisionText(item,key){const decision=historyDecision(item);return decision&&hasValue(decision[key])?text(decision[key]):'UNAVAILABLE';}
function historyTone(state){if(state==='completed')return'low';if(state==='failed')return'critical';if(state==='running')return'medium';if(state==='queued')return'info';return'warning';}
function domNode(tag,className,value){const node=document.createElement(tag);if(className)node.className=className;if(value!==undefined)node.textContent=String(value);return node;}
function clearNode(host){while(host?.firstChild)host.removeChild(host.firstChild);}

function renderLatestInvestigation(items){
  const host=$('workspaceLatestReport');if(!host)return;clearNode(host);
  if(!Array.isArray(items)){host.append(domNode('div','workspace-command-empty','Canonical investigation history is unavailable. Missing history is not treated as an empty vault.'));return;}
  const latest=items[0]||null;
  if(!latest){host.append(domNode('div','workspace-command-empty','No canonical investigation job is retained yet. Start at Deep Scan to create a metered investigation.'));return;}
  const state=historyState(latest.status),target=text(latest.target),network=text(latest.network),evidence=historyEvidenceState(latest),verdict=historyDecisionText(latest,'verdict'),grade=historyDecisionText(latest,'grade');
  const card=domNode('article','workspace-report-card');
  const top=domNode('div','workspace-report-card__top'),identity=domNode('div');
  identity.append(domNode('b','',target||'Target unavailable'),domNode('span','',`Queued ${strictWhen(latest.queued_at)} · ${network||'NETWORK UNAVAILABLE'}`));
  top.append(identity,domNode('span',`workspace-report-badge ${historyTone(state)}`,state==='unknown'?'UNAVAILABLE':state.toUpperCase()));
  const meta=domNode('div','workspace-report-meta');
  for(const [label,value] of [['Verdict',verdict],['Grade',grade],['Evidence',evidence]]){const wrap=domNode('div');wrap.append(domNode('label','',label),domNode('strong','',value));meta.append(wrap);}
  const actions=domNode('div','workspace-report-actions');
  if(target){const reinvestigate=domNode('a','primary','Re-investigate target');reinvestigate.href=`/scan?mode=deep&target=${encodeURIComponent(target)}`;actions.append(reinvestigate);}
  const historyLink=domNode('a','','Open investigation history');historyLink.href='/reports';actions.append(historyLink);
  card.append(top,meta,actions);host.append(card);
}

function renderAlerts(items){
  const host=$('workspaceAlerts');if(!host)return;
  const latest=[...items].sort((a,b)=>Date.parse(b?.created_at||0)-Date.parse(a?.created_at||0)).slice(0,4);
  if(!latest.length){host.innerHTML='<div class="workspace-command-empty">No watchlist alert is currently returned for this account.</div>';return;}
  host.innerHTML=`<div class="workspace-alert-list">${latest.map(item=>{const severity=normalizedTone(item.severity||'info');return`<article class="workspace-alert" data-severity="${esc(severity)}"><div class="workspace-alert__top"><b>${esc(item.title||item.label||'Watchlist signal')}</b><em>${esc(severity)}</em></div><p>${esc(item.message||item.target||'A monitored target changed.')}</p><small>${esc(when(item.created_at))}</small></article>`}).join('')}</div>`;
}

function renderSignedOut(){
  const state=$('workspaceLiveState');if(state){state.dataset.state='signed_out';state.textContent='SIGN IN FOR LIVE DATA';}
  setKPI('workspaceAccessKpi','SIGNED OUT','Account data is private.');
  setKPI('workspaceReportsKpi','—','Sign in to read canonical investigation history.');
  setKPI('workspaceWatchKpi','—','Sign in to read monitored targets.');
  setKPI('workspaceAlertsKpi','—','Sign in to read alert state.');
  const latest=$('workspaceLatestReport');clearNode(latest);latest?.append(domNode('div','workspace-command-empty','Sign in to continue from your latest canonical investigation.'));
  $('workspaceAlerts').innerHTML='<div class="workspace-command-empty">Watchlist alerts are account-scoped and are not exposed while signed out.</div>';
  const signIn=$('workspaceSignIn');if(signIn)signIn.hidden=false;
}

async function load(){
  if(!window.KoscheiAuth)return;
  try{await KoscheiAuth.init();}catch{}
  const link=$('sessionLink');
  if(!KoscheiAuth.isLoggedIn()){
    renderSignedOut();return;
  }
  if(link){link.href='/account';link.textContent='Account';}
  const signIn=$('workspaceSignIn');if(signIn)signIn.hidden=true;
  const email=KoscheiAuth.getEmail?.();
  const state=$('workspaceLiveState');if(state){state.dataset.state='partial';state.textContent=email?`LOADING · ${email}`:'LOADING ACCOUNT';}

  const [accessResult,historyResultResponse,watchResult,alertsResult]=await Promise.all([
    read('/api/auth/premium-access'),
    read('/api/v1/radar/jobs/'),
    read('/api/watchlist'),
    read('/api/watchlist/alerts')
  ]);

  const access=obj(accessResult.data?.access),active=accessResult.ok&&access.active===true;
  const tier=text(access.token_tier||'none').toUpperCase();
  const tokenAmount=access.token_amount;
  setKPI('workspaceAccessKpi',active?tier:'INACTIVE',active?`${displayNumber(tokenAmount)} KOSCH verified`:(accessResult.ok?'Verified holder access is not active.':'Access service unavailable.'),active?'good':accessResult.ok?'warn':'bad');

  const investigationHistory=historyFrom(historyResultResponse),historyAvailable=Array.isArray(investigationHistory);
  setKPI('workspaceReportsKpi',historyAvailable?String(investigationHistory.length):'—',historyAvailable?(investigationHistory.length?'Durable canonical jobs returned by account history.':'No canonical investigation job retained yet.'):(historyResultResponse.status===401||historyResultResponse.status===402||historyResultResponse.status===403?'Basic KOSCH holder access required.':'Investigation history unavailable.'),historyAvailable?'good':historyResultResponse.status===401||historyResultResponse.status===402||historyResultResponse.status===403?'warn':'bad');

  const targets=watchResult.ok?targetsFrom(watchResult):[];
  const maxTargets=watchResult.data?.max_targets;
  setKPI('workspaceWatchKpi',watchResult.ok?`${targets.length}${Number.isFinite(Number(maxTargets))?`/${maxTargets}`:''}`:'—',watchResult.ok?(targets.length?'Targets under structural monitoring.':'No monitored target yet.'):(watchResult.status===402||watchResult.status===403?'KOSCH holder access required.':'Watchlist service unavailable.'),watchResult.ok?'good':watchResult.status===402||watchResult.status===403?'warn':'bad');

  const alerts=alertsResult.ok?alertsFrom(alertsResult):[];
  const unread=alerts.filter(item=>!text(item.read_at)&&item.read!==true&&item.is_read!==true).length;
  setKPI('workspaceAlertsKpi',alertsResult.ok?String(unread):'—',alertsResult.ok?(alerts.length?`${alerts.length} recent alert record(s) returned.`:'No alert record returned.'):(alertsResult.status===402||alertsResult.status===403?'KOSCH holder access required.':'Alert service unavailable.'),alertsResult.ok&&unread===0?'good':alertsResult.ok?'warn':alertsResult.status===402||alertsResult.status===403?'warn':'bad');

  renderLatestInvestigation(investigationHistory);
  renderAlerts(alerts);
  const availableSources=[accessResult.ok,historyAvailable,watchResult.ok,alertsResult.ok].filter(Boolean).length;
  if(state){
    state.dataset.state=availableSources===4?'live':'partial';
    state.textContent=availableSources===4?'LIVE ACCOUNT DATA':`${availableSources}/4 DATA SOURCES AVAILABLE`;
  }
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',load);else load();
})();
