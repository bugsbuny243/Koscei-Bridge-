(()=>{
'use strict';
if(window.__koscheiCustomerWatchlistV2)return;
window.__koscheiCustomerWatchlistV2=true;

const $=id=>document.getElementById(id);
const arr=value=>Array.isArray(value)?value:[];
const text=value=>String(value??'').trim();
const lower=value=>text(value).toLowerCase();
const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const when=value=>{const parsed=new Date(value||0);return Number.isNaN(parsed.getTime())?'—':new Intl.DateTimeFormat('en-US',{dateStyle:'medium',timeStyle:'short'}).format(parsed);};
let targets=[],alerts=[],maxTargets=null;

function severity(value){const raw=lower(value);return ['info','low','warning','medium','high','critical'].includes(raw)?raw:'info';}
function status(message,tone=''){const node=$('watchStatus');if(!node)return;node.textContent=message;node.className=`ops-status show${tone?` ${tone}`:''}`;}
function clearStatus(){const node=$('watchStatus');if(node)node.className='ops-status';}
function setKPI(id,value,detail,tone=''){const node=$(id);if(!node)return;node.dataset.tone=tone;node.querySelector('strong').textContent=value;node.querySelector('small').textContent=detail;}
function unread(item){return !text(item?.read_at)&&item?.read!==true&&item?.is_read!==true;}

async function api(path,options={}){
  const response=await KoscheiAuth.apiCall(path,{...options,headers:{'Content-Type':'application/json',...(options.headers||{})}});
  const data=await response.json().catch(()=>({}));
  if(!response.ok){const error=new Error(data.message||data.error||([402,403].includes(response.status)?'Active KOSCH holder access is required.':'The monitoring operation failed.'));error.status=response.status;throw error;}
  return data;
}

function updateKPIs(){
  const active=targets.filter(item=>lower(item.status||'active')==='active').length;
  const unreadCount=alerts.filter(unread).length;
  const checked=targets.map(item=>Date.parse(item.last_checked_at||0)).filter(Number.isFinite).sort((a,b)=>b-a)[0];
  setKPI('watchTargetsKpi',maxTargets?`${targets.length}/${maxTargets}`:String(targets.length),targets.length?'Targets returned by your monitoring list.':'No monitored target yet.',targets.length?'good':'');
  setKPI('watchActiveKpi',String(active),active?'Targets currently marked active.':'No active target.',active?'good':'warn');
  setKPI('watchUnreadKpi',String(unreadCount),unreadCount?'Alert records still requiring review.':'No unread alert record returned.',unreadCount?'warn':'good');
  setKPI('watchCheckedKpi',checked?when(checked):'—',checked?'Most recent target check timestamp.':'No completed target check timestamp.',checked?'good':'');
}

function targetMatches(item,query){return !query||lower(`${item.label||''} ${item.target||''} ${item.status||''} ${item.last_risk_level||''}`).includes(query);}
function alertMatches(item,query){return !query||lower(`${item.title||''} ${item.label||''} ${item.target||''} ${item.message||''} ${item.severity||''}`).includes(query);}

function renderTargets(){
  const host=$('watchTargets'),query=lower($('watchSearch')?.value),filtered=targets.filter(item=>targetMatches(item,query));
  $('watchTargetCount').textContent=`${filtered.length}/${targets.length}`;
  if(!filtered.length){host.innerHTML='<div class="ops-empty">No monitored target matches the current search.</div>';return;}
  host.innerHTML=filtered.map(item=>{
    const active=lower(item.status||'active')==='active',risk=severity(item.last_risk_level||'info'),score=Number.isFinite(Number(item.last_score))?Number(item.last_score):null,id=encodeURIComponent(text(item.id));
    return`<article class="ops-record ops-monitor-card"><div class="ops-record-head"><div class="ops-record-title"><span>${active?'ACTIVE MONITOR':'PAUSED MONITOR'}</span><b>${esc(item.label||'Token')}</b><div class="ops-address">${esc(item.target||'Target unavailable')}</div></div><span class="ops-risk ${esc(risk)}">${esc(risk)}</span></div><div class="ops-record-meta"><div><label>Last score</label><strong class="ops-score">${score===null?'—':esc(score)}</strong></div><div><label>Alert threshold</label><strong>${Number.isFinite(Number(item.alert_threshold))?esc(item.alert_threshold):'—'}</strong></div><div><label>Last checked</label><strong>${esc(when(item.last_checked_at))}</strong></div></div><div class="ops-record-actions"><button class="ops-btn primary" type="button" data-watch-action="refresh" data-watch-id="${id}">Refresh evidence</button><button class="ops-btn" type="button" data-watch-action="toggle" data-watch-id="${id}" data-watch-next="${active?'paused':'active'}">${active?'Pause':'Resume'}</button><button class="ops-btn danger" type="button" data-watch-action="delete" data-watch-id="${id}" data-watch-label="${esc(item.label||item.target||'target')}">Remove</button>${item.target?`<a class="ops-btn" href="/scan?mode=token&target=${encodeURIComponent(item.target)}">Open scan</a>`:''}</div></article>`;
  }).join('');
}

function renderAlerts(){
  const host=$('watchAlerts'),query=lower($('watchSearch')?.value),filtered=[...alerts].filter(item=>alertMatches(item,query)).sort((a,b)=>Date.parse(b?.created_at||0)-Date.parse(a?.created_at||0));
  $('watchAlertCount').textContent=`${filtered.length}/${alerts.length}`;
  if(!filtered.length){host.innerHTML='<div class="ops-empty">No alert matches the current search.</div>';return;}
  host.innerHTML=filtered.map(item=>{const sev=severity(item.severity),isRead=!unread(item);return`<article class="ops-record ops-alert" data-severity="${esc(sev)}" data-read="${isRead}"><div class="ops-record-head"><div class="ops-record-title"><span>${isRead?'REVIEWED ALERT':'ATTENTION REQUIRED'}</span><b>${esc(item.title||'Monitoring alert')}</b><small>${esc(item.label||item.target||'Monitored target')} · ${esc(when(item.created_at))}</small></div><span class="ops-risk ${esc(sev)}">${esc(sev)}</span></div><p class="ops-record-copy">${esc(item.message||'A monitored target produced a change alert.')}</p></article>`;}).join('');
}

function render(){updateKPIs();renderTargets();renderAlerts();}

async function load(){
  clearStatus();
  try{
    const [targetData,alertData]=await Promise.all([api('/api/watchlist'),api('/api/watchlist/alerts')]);
    targets=arr(targetData.targets);alerts=arr(alertData.alerts);maxTargets=Number.isFinite(Number(targetData.max_targets))?Number(targetData.max_targets):null;render();
  }catch(error){
    targets=[];alerts=[];maxTargets=null;render();status(error.message||'Monitoring data is unavailable. No target or alert count was inferred.','bad');
  }
}

async function runButton(button,work){
  if(button.disabled)return;const previous=button.textContent;button.disabled=true;button.textContent='Working…';
  try{await work();}finally{button.disabled=false;button.textContent=previous;}
}

async function handleAction(button){
  const action=button.dataset.watchAction,id=button.dataset.watchId;if(!action||!id)return;
  if(action==='delete'&&!confirm(`Remove ${button.dataset.watchLabel||'this target'} from monitoring?`))return;
  await runButton(button,async()=>{
    try{
      if(action==='refresh')await api(`/api/watchlist/${id}/refresh`,{method:'POST',body:'{}'});
      if(action==='toggle')await api(`/api/watchlist/${id}`,{method:'PATCH',body:JSON.stringify({status:button.dataset.watchNext})});
      if(action==='delete')await api(`/api/watchlist/${id}`,{method:'DELETE'});
      status(action==='delete'?'Monitoring target removed.':'Monitoring state updated.','good');await load();
    }catch(error){status(error.message,'bad');}
  });
}

async function bootstrap(){
  try{await KoscheiAuth.init();}catch{}
  if(!KoscheiAuth.requireAuth('/login'))return;
  $('watchForm')?.addEventListener('submit',async event=>{
    event.preventDefault();const button=$('watchAddButton'),target=text($('watchTarget').value),label=text($('watchLabel').value),threshold=Number($('watchThreshold').value||50);if(!target)return;
    await runButton(button,async()=>{try{await api('/api/watchlist',{method:'POST',body:JSON.stringify({target,target_type:'token',network:'solana-mainnet',label,alert_threshold:threshold})});$('watchTarget').value='';status('Target added to structural monitoring.','good');await load();}catch(error){status(error.message,'bad');}});
  });
  $('watchRefreshAll')?.addEventListener('click',event=>runButton(event.currentTarget,async()=>{try{await api('/api/watchlist/refresh?limit=5',{method:'POST',body:'{}'});status('Bounded refresh requested for up to five monitored targets.','good');await load();}catch(error){status(error.message,'bad');}}));
  $('watchMarkRead')?.addEventListener('click',event=>runButton(event.currentTarget,async()=>{try{await api('/api/watchlist/alerts',{method:'POST',body:'{}'});status('Alert records marked reviewed.','good');await load();}catch(error){status(error.message,'bad');}}));
  $('watchReload')?.addEventListener('click',load);$('watchSearch')?.addEventListener('input',render);
  document.addEventListener('click',event=>{const button=event.target.closest('[data-watch-action]');if(button)handleAction(button);});
  await load();
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bootstrap);else bootstrap();
})();
