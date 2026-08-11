(()=>{
'use strict';
if(window.__koscheiCustomerWatchlistV2)return;
window.__koscheiCustomerWatchlistV2=true;

const $=id=>document.getElementById(id);
const text=value=>String(value??'').trim();
const lower=value=>text(value).toLowerCase();
const hasValue=value=>value!==null&&value!==undefined&&String(value).trim()!=='';
const numberOrNull=value=>{if(value===null||value===undefined||value==='')return null;const parsed=Number(value);return Number.isFinite(parsed)?parsed:null;};
const allowedSeverities=new Set(['info','low','medium','high','critical']);
let targets=null,alerts=null,maxTargets=null;

function severity(value){const raw=lower(value);return allowedSeverities.has(raw)?raw:'unknown';}
function alertReviewState(item){const raw=lower(item?.status);if(raw==='new')return'unread';if(raw==='read')return'read';return'unknown';}
function when(value){if(!hasValue(value))return'—';const parsed=new Date(value);return Number.isNaN(parsed.getTime())?'—':new Intl.DateTimeFormat('en-US',{dateStyle:'medium',timeStyle:'short'}).format(parsed);}
function node(tag,className,value){const el=document.createElement(tag);if(className)el.className=className;if(value!==undefined)el.textContent=String(value);return el;}
function clear(host){while(host?.firstChild)host.removeChild(host.firstChild);}
function status(message,tone=''){const host=$('watchStatus');if(!host)return;host.textContent=message;host.className=`ops-status show${tone?` ${tone}`:''}`;}
function clearStatus(){const host=$('watchStatus');if(host){host.textContent='';host.className='ops-status';}}
function setKPI(id,value,detail,tone=''){const host=$(id);if(!host)return;host.dataset.tone=tone;host.querySelector('strong').textContent=value;host.querySelector('small').textContent=detail;}
function setTargetKPIsUnavailable(detail){setKPI('watchTargetsKpi','—',detail,'bad');setKPI('watchActiveKpi','—',detail,'bad');setKPI('watchCheckedKpi','—',detail,'bad');const count=$('watchTargetCount');if(count)count.textContent='—/—';}
function setAlertKPIUnavailable(detail){setKPI('watchUnreadKpi','—',detail,'bad');const count=$('watchAlertCount');if(count)count.textContent='—/—';}

async function api(path,options={}){
  const headers={...(options.headers||{})};
  if(options.body!==undefined&&!headers['Content-Type'])headers['Content-Type']='application/json';
  const response=await KoscheiAuth.apiCall(path,{...options,headers});
  let data={};const raw=await response.text();if(raw){try{data=JSON.parse(raw);}catch{data={error:'invalid_json_response'};}}
  if(!response.ok){const access=[401,402,403].includes(response.status)?'Pro KOSCH tier or higher, a verified customer session, and available monitoring quota are required. ':'';const error=new Error(access+text(data?.message||data?.error||`Monitoring request failed with HTTP ${response.status}`));error.status=response.status;throw error;}
  return data;
}

function updateKPIs(){
  if(!Array.isArray(targets))setTargetKPIsUnavailable('Monitoring target collection unavailable; no target state inferred.');
  else{
    const cap=maxTargets===null?'UNAVAILABLE':maxTargets;
    setKPI('watchTargetsKpi',`${targets.length}/${cap}`,targets.length?'Server-returned monitoring targets and capacity.':'No monitored target returned.',targets.length?'good':'');
    const states=targets.map(item=>lower(item?.status));
    if(states.some(value=>value!=='active'&&value!=='paused'))setKPI('watchActiveKpi','—','At least one target has unavailable status evidence.','bad');
    else{const active=states.filter(value=>value==='active').length;setKPI('watchActiveKpi',String(active),active?'Targets explicitly marked active.':'No target explicitly marked active.',active?'good':'warn');}
    const timestampValues=targets.map(item=>item?.last_checked_at).filter(hasValue);
    const parsed=timestampValues.map(value=>Date.parse(value));
    if(parsed.some(value=>!Number.isFinite(value)))setKPI('watchCheckedKpi','—','At least one returned check timestamp is invalid.','bad');
    else{const latest=parsed.sort((a,b)=>b-a)[0];setKPI('watchCheckedKpi',latest===undefined?'—':when(latest),latest===undefined?'No completed target check timestamp returned.':'Most recent server-returned target check timestamp.',latest===undefined?'':'good');}
  }

  if(!Array.isArray(alerts))setAlertKPIUnavailable('Alert collection unavailable; no unread count inferred.');
  else{
    const states=alerts.map(alertReviewState);
    if(states.includes('unknown'))setKPI('watchUnreadKpi','—','At least one alert has unavailable review-state evidence.','bad');
    else{const unreadCount=states.filter(value=>value==='unread').length;setKPI('watchUnreadKpi',String(unreadCount),unreadCount?'Alert records explicitly marked new.':'No alert record explicitly marked new.',unreadCount?'warn':'good');}
  }
}

function targetMatches(item,query){return !query||lower(`${item?.label||''} ${item?.target||''} ${item?.status||''} ${item?.last_risk_level||''}`).includes(query);}
function alertMatches(item,query){return !query||lower(`${item?.title||''} ${item?.label||''} ${item?.target||''} ${item?.message||''} ${item?.severity||''} ${item?.status||''}`).includes(query);}
function actionButton(label,action,id,extra=''){const button=node('button',`ops-btn ${extra}`.trim(),label);button.type='button';button.dataset.watchAction=action;button.dataset.watchId=id;return button;}
function meta(label,value,score=false){const wrap=node('div');wrap.append(node('label','',label),node('strong',score?'ops-score':'',value));return wrap;}

function renderTargets(){
  const host=$('watchTargets'),count=$('watchTargetCount');clear(host);
  if(!Array.isArray(targets)){count.textContent='—/—';host.append(node('div','ops-empty','Monitored-target collection is unavailable. No empty-list state is inferred.'));return;}
  const query=lower($('watchSearch')?.value),filtered=targets.filter(item=>targetMatches(item,query));count.textContent=`${filtered.length}/${targets.length}`;
  if(filtered.length===0){host.append(node('div','ops-empty',targets.length?'No monitored target matches the current search.':'No monitored targets are registered for this account.'));return;}
  for(const item of filtered){
    const id=text(item?.id),target=text(item?.target),targetStatus=lower(item?.status),knownStatus=targetStatus==='active'||targetStatus==='paused';
    const risk=severity(item?.last_risk_level),score=numberOrNull(item?.last_score),threshold=numberOrNull(item?.alert_threshold);
    const card=node('article','ops-record ops-monitor-card');const head=node('div','ops-record-head');const title=node('div','ops-record-title');
    title.append(node('span','',knownStatus?(targetStatus==='active'?'ACTIVE MONITOR':'PAUSED MONITOR'):'MONITOR STATUS UNAVAILABLE'),node('b','',text(item?.label)||'Token'),node('div','ops-address',target||'Target unavailable'));
    head.append(title,node('span',`ops-risk ${risk==='unknown'?'':risk}`.trim(),risk==='unknown'?'UNAVAILABLE':risk));
    const metadata=node('div','ops-record-meta');metadata.append(meta('Last score',score===null?'—':score,true),meta('Alert threshold',threshold===null?'—':threshold),meta('Last checked',when(item?.last_checked_at)));
    const actions=node('div','ops-record-actions');
    if(id){actions.append(actionButton('Refresh evidence','refresh',id,'primary'));if(knownStatus){const toggle=actionButton(targetStatus==='active'?'Pause':'Resume','toggle',id);toggle.dataset.watchNext=targetStatus==='active'?'paused':'active';actions.append(toggle);}const remove=actionButton('Remove','delete',id,'danger');remove.dataset.watchLabel=text(item?.label)||target||'target';actions.append(remove);}
    if(target){const link=node('a','ops-btn','Open scan');link.href=`/scan?mode=token&target=${encodeURIComponent(target)}`;actions.append(link);}
    card.append(head,metadata,actions);host.append(card);
  }
}

function renderAlerts(){
  const host=$('watchAlerts'),count=$('watchAlertCount');clear(host);
  if(!Array.isArray(alerts)){count.textContent='—/—';host.append(node('div','ops-empty','Alert collection is unavailable. No empty attention queue is inferred.'));return;}
  const query=lower($('watchSearch')?.value),filtered=[...alerts].filter(item=>alertMatches(item,query)).sort((a,b)=>(Date.parse(b?.created_at)||0)-(Date.parse(a?.created_at)||0));count.textContent=`${filtered.length}/${alerts.length}`;
  if(filtered.length===0){host.append(node('div','ops-empty',alerts.length?'No alert matches the current search.':'No alert records are retained for this account.'));return;}
  for(const item of filtered){
    const sev=severity(item?.severity),review=alertReviewState(item);const card=node('article','ops-record ops-alert');card.dataset.severity=sev;card.dataset.read=review==='read'?'true':review==='unread'?'false':'unknown';
    const head=node('div','ops-record-head'),title=node('div','ops-record-title');title.append(node('span','',review==='read'?'REVIEWED ALERT':review==='unread'?'ATTENTION REQUIRED':'REVIEW STATE UNAVAILABLE'),node('b','',text(item?.title)||'Monitoring alert'),node('small','',`${text(item?.label||item?.target)||'Monitored target'} · ${when(item?.created_at)}`));
    head.append(title,node('span',`ops-risk ${sev==='unknown'?'':sev}`.trim(),sev==='unknown'?'UNAVAILABLE':sev));card.append(head,node('p','ops-record-copy',text(item?.message)||'Alert message unavailable.'));host.append(card);
  }
}

function render(){updateKPIs();renderTargets();renderAlerts();}

async function load({preserveStatus=false}={}){
  if(!preserveStatus)clearStatus();
  try{
    const [targetData,alertData]=await Promise.all([api('/api/watchlist'),api('/api/watchlist/alerts')]);
    targets=Array.isArray(targetData?.targets)?targetData.targets:null;alerts=Array.isArray(alertData?.alerts)?alertData.alerts:null;const parsedMax=numberOrNull(targetData?.max_targets);maxTargets=parsedMax!==null&&parsedMax>=0?parsedMax:null;render();
    if(targets===null||alerts===null)status('Monitoring response is incomplete. Missing collections remain unavailable and are not treated as empty.','bad');
  }catch(error){targets=null;alerts=null;maxTargets=null;render();status(error.message||'Monitoring data is unavailable. No target or alert count was inferred.','bad');}
}

async function runButton(button,work){if(button.disabled)return;const previous=button.textContent;button.disabled=true;button.textContent='Working…';try{await work();}finally{button.disabled=false;button.textContent=previous;}}

async function handleAction(button){
  const action=button.dataset.watchAction,id=button.dataset.watchId;if(!action||!id)return;
  if(action==='delete'&&!window.confirm(`Remove ${button.dataset.watchLabel||'this target'} from monitoring?`))return;
  await runButton(button,async()=>{
    try{
      if(action==='refresh'){const data=await api(`/api/watchlist/${encodeURIComponent(id)}/refresh`,{method:'POST',body:'{}'});if(data?.ok!==true)throw new Error('Refresh response was incomplete; no successful refresh is inferred.');status('Evidence refresh completed.','good');}
      if(action==='toggle'){const next=button.dataset.watchNext;if(next!=='active'&&next!=='paused')throw new Error('Target status evidence is unavailable; no state change was sent.');await api(`/api/watchlist/${encodeURIComponent(id)}`,{method:'PATCH',body:JSON.stringify({status:next})});status(`Monitoring target ${next}.`,'good');}
      if(action==='delete'){await api(`/api/watchlist/${encodeURIComponent(id)}`,{method:'DELETE'});status('Monitoring target removed.','good');}
      await load({preserveStatus:true});
    }catch(error){status(error.message,'bad');}
  });
}

async function bootstrap(){
  try{await KoscheiAuth.init();}catch{}
  if(!KoscheiAuth.requireAuth('/login.html'))return;
  $('watchForm')?.addEventListener('submit',async event=>{
    event.preventDefault();const button=$('watchAddButton'),target=text($('watchTarget').value),label=text($('watchLabel').value),thresholdRaw=text($('watchThreshold').value),threshold=Number(thresholdRaw);if(!target)return;if(!Number.isInteger(threshold)||threshold<1||threshold>100){status('Alert threshold must be an explicit integer from 1 to 100.','bad');return;}
    await runButton(button,async()=>{try{const data=await api('/api/watchlist',{method:'POST',body:JSON.stringify({target,target_type:'token',network:'solana-mainnet',label,alert_threshold:threshold})});$('watchTarget').value='';if(hasValue(data?.refresh_error))status(`Target added, but initial evidence refresh was unavailable: ${text(data.refresh_error)}`,'bad');else if(data?.created===true)status('Target added to structural monitoring and initial refresh returned without an error marker.','good');else status('Target request completed, but the create response was incomplete.','bad');await load({preserveStatus:true});}catch(error){status(error.message,'bad');}});
  });
  $('watchRefreshAll')?.addEventListener('click',event=>runButton(event.currentTarget,async()=>{try{const data=await api('/api/watchlist/refresh?limit=5',{method:'POST',body:'{}'});if(!Array.isArray(data?.results)){status('Batch refresh response is incomplete; no successful refresh count is inferred.','bad');await load({preserveStatus:true});return;}const failed=data.results.filter(item=>lower(item?.status)==='failed').length,unknown=data.results.filter(item=>!['completed','failed'].includes(lower(item?.status))).length;if(failed||unknown)status(`Batch refresh returned ${failed} failed and ${unknown} unavailable result states out of ${data.results.length}.`,'bad');else status(`Evidence refresh completed for ${data.results.length} monitored target(s).`,'good');await load({preserveStatus:true});}catch(error){status(error.message,'bad');}}));
  $('watchMarkRead')?.addEventListener('click',event=>runButton(event.currentTarget,async()=>{try{const data=await api('/api/watchlist/alerts',{method:'POST',body:'{}'});const marked=numberOrNull(data?.marked_read);if(marked===null)status('Review-state response is incomplete; no alert count is inferred.','bad');else status(`${marked} alert record(s) marked reviewed.`,'good');await load({preserveStatus:true});}catch(error){status(error.message,'bad');}}));
  $('watchReload')?.addEventListener('click',()=>load());$('watchSearch')?.addEventListener('input',()=>{renderTargets();renderAlerts();});
  document.addEventListener('click',event=>{const button=event.target.closest('[data-watch-action]');if(button)handleAction(button);});
  await load();
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bootstrap);else bootstrap();
})();
