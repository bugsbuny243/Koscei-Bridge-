(()=>{
'use strict';
if(window.__koscheiCustomerWorkspaceV2)return;
window.__koscheiCustomerWorkspaceV2=true;

const $=id=>document.getElementById(id);
const arr=value=>Array.isArray(value)?value:[];
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const text=value=>String(value??'').trim();
const displayNumber=value=>Number.isFinite(Number(value))?new Intl.NumberFormat('en-US',{maximumFractionDigits:2}).format(Number(value)):'—';
const when=value=>{const parsed=new Date(value||0);return Number.isNaN(parsed.getTime())?'—':new Intl.DateTimeFormat('en-US',{dateStyle:'medium',timeStyle:'short'}).format(parsed);};

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

function reportsFrom(result){return arr(result?.data?.reports).length?arr(result.data.reports):arr(obj(result?.data?.data).reports);}
function targetsFrom(result){return arr(result?.data?.targets);}
function alertsFrom(result){return arr(result?.data?.alerts);}

function latestBy(items,field){
  return [...items].sort((a,b)=>Date.parse(b?.[field]||0)-Date.parse(a?.[field]||0))[0]||null;
}

function renderLatestReport(items){
  const host=$('workspaceLatestReport');if(!host)return;
  const latest=latestBy(items,'created_at');
  if(!latest){host.innerHTML='<div class="workspace-command-empty">No signed report is available yet. Start at the canonical Scan Center; a durable report appears only when its evidence contract allows it.</div>';return;}
  const target=text(latest.target_id||latest.target||''),type=text(latest.target_type||'target'),risk=text(latest.risk_level||'signed').toLowerCase();
  const score=latest.overall_score??latest.score??latest.risk_index;
  const signals=obj(latest.signals),floor=signals.structural_floor;
  host.innerHTML=`<article class="workspace-report-card"><div class="workspace-report-card__top"><div><b>${esc(type.toUpperCase())} · ${esc(target||'Target unavailable')}</b><span>${esc(when(latest.created_at))}</span></div><span class="workspace-report-badge ${esc(risk)}">${esc(risk.toUpperCase())}</span></div><div class="workspace-report-meta"><div><label>Score</label><strong>${esc(score??'—')}</strong></div><div><label>Structural floor</label><strong>${esc(floor??'—')}</strong></div><div><label>Evidence</label><strong>${latest.signature||latest.signed?'SIGNED':'DURABLE'}</strong></div></div><div class="workspace-report-actions">${target?`<a class="primary" href="/scan?mode=token&target=${encodeURIComponent(target)}">Re-investigate target</a>`:''}<a href="/reports">Open report vault</a></div></article>`;
}

function renderAlerts(items){
  const host=$('workspaceAlerts');if(!host)return;
  const latest=[...items].sort((a,b)=>Date.parse(b?.created_at||0)-Date.parse(a?.created_at||0)).slice(0,4);
  if(!latest.length){host.innerHTML='<div class="workspace-command-empty">No watchlist alert is currently returned for this account.</div>';return;}
  host.innerHTML=`<div class="workspace-alert-list">${latest.map(item=>{const severity=text(item.severity||'info').toLowerCase();return`<article class="workspace-alert" data-severity="${esc(severity)}"><div class="workspace-alert__top"><b>${esc(item.title||item.label||'Watchlist signal')}</b><em>${esc(severity)}</em></div><p>${esc(item.message||item.target||'A monitored target changed.')}</p><small>${esc(when(item.created_at))}</small></article>`}).join('')}</div>`;
}

function renderSignedOut(){
  const state=$('workspaceLiveState');if(state){state.dataset.state='signed_out';state.textContent='SIGN IN FOR LIVE DATA';}
  setKPI('workspaceAccessKpi','SIGNED OUT','Account data is private.');
  setKPI('workspaceReportsKpi','—','Sign in to read report history.');
  setKPI('workspaceWatchKpi','—','Sign in to read monitored targets.');
  setKPI('workspaceAlertsKpi','—','Sign in to read alert state.');
  $('workspaceLatestReport').innerHTML='<div class="workspace-command-empty">Sign in to continue from your latest durable investigation.</div>';
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

  const [accessResult,reportsResult,watchResult,alertsResult]=await Promise.all([
    read('/api/auth/premium-access'),
    read('/api/v1/unified/reports'),
    read('/api/watchlist'),
    read('/api/watchlist/alerts')
  ]);

  const access=obj(accessResult.data?.access),active=accessResult.ok&&access.active===true;
  const tier=text(access.token_tier||'none').toUpperCase();
  const tokenAmount=access.token_amount;
  setKPI('workspaceAccessKpi',active?tier:'INACTIVE',active?`${displayNumber(tokenAmount)} KOSCH verified`:(accessResult.ok?'Verified holder access is not active.':'Access service unavailable.'),active?'good':accessResult.ok?'warn':'bad');

  const reports=reportsResult.ok?reportsFrom(reportsResult):[];
  setKPI('workspaceReportsKpi',reportsResult.ok?String(reports.length):'—',reportsResult.ok?(reports.length?'Durable reports returned by the vault.':'No durable signed report yet.'):'Report service unavailable.',reportsResult.ok?'good':'bad');

  const targets=watchResult.ok?targetsFrom(watchResult):[];
  const maxTargets=watchResult.data?.max_targets;
  setKPI('workspaceWatchKpi',watchResult.ok?`${targets.length}${Number.isFinite(Number(maxTargets))?`/${maxTargets}`:''}`:'—',watchResult.ok?(targets.length?'Targets under structural monitoring.':'No monitored target yet.'):(watchResult.status===402||watchResult.status===403?'KOSCH holder access required.':'Watchlist service unavailable.'),watchResult.ok?'good':watchResult.status===402||watchResult.status===403?'warn':'bad');

  const alerts=alertsResult.ok?alertsFrom(alertsResult):[];
  const unread=alerts.filter(item=>item.read_at==null&&item.read!==true&&item.is_read!==true).length;
  setKPI('workspaceAlertsKpi',alertsResult.ok?String(unread):'—',alertsResult.ok?(alerts.length?`${alerts.length} recent alert record(s) returned.`:'No alert record returned.'):(alertsResult.status===402||alertsResult.status===403?'KOSCH holder access required.':'Alert service unavailable.'),alertsResult.ok&&unread===0?'good':alertsResult.ok?'warn':alertsResult.status===402||alertsResult.status===403?'warn':'bad');

  renderLatestReport(reports);
  renderAlerts(alerts);
  const okCount=[accessResult,reportsResult,watchResult,alertsResult].filter(result=>result.ok).length;
  if(state){
    state.dataset.state=okCount===4?'live':'partial';
    state.textContent=okCount===4?'LIVE ACCOUNT DATA':`${okCount}/4 DATA SOURCES AVAILABLE`;
  }
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',load);else load();
})();
