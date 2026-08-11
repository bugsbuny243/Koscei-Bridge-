(()=>{
'use strict';
if(window.__koscheiCustomerReportsV2)return;
window.__koscheiCustomerReportsV2=true;

const $=id=>document.getElementById(id);
const arr=value=>Array.isArray(value)?value:[];
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const text=value=>String(value??'').trim();
const lower=value=>text(value).toLowerCase();
const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const when=value=>{const parsed=new Date(value||0);return Number.isNaN(parsed.getTime())?'—':new Intl.DateTimeFormat('en-US',{dateStyle:'medium',timeStyle:'short'}).format(parsed);};
const short=value=>{const raw=text(value);return raw.length>28?`${raw.slice(0,12)}…${raw.slice(-10)}`:raw||'—';};
let reports=[];

function normalizedRisk(value){const risk=lower(value);return ['low','medium','high','critical','unknown'].includes(risk)?risk:'unknown';}
function scanURL(type,target){const kind=lower(type),encoded=encodeURIComponent(target);if(kind==='token'||kind==='mint')return`/scan?mode=token&target=${encoded}`;if(kind==='wallet')return`/scan?mode=deep&kind=wallet&target=${encoded}`;if(kind==='site'||kind==='url')return`/scan?mode=deep&kind=site&target=${encoded}`;return`/scan?mode=quick&target=${encoded}`;}
function reportSignals(item){return obj(item?.signals||obj(item?.module_results).signals||item?.module_results);}
function scoreOf(item){const raw=item?.overall_score??item?.score??item?.risk_index;return Number.isFinite(Number(raw))?Number(raw):null;}
function status(message,tone=''){const node=$('reportsStatus');if(!node)return;node.textContent=message;node.className=`ops-status show${tone?` ${tone}`:''}`;}
function clearStatus(){const node=$('reportsStatus');if(node)node.className='ops-status';}
function setKPI(id,value,detail,tone=''){const node=$(id);if(!node)return;node.dataset.tone=tone;node.querySelector('strong').textContent=value;node.querySelector('small').textContent=detail;}
function setUnavailableKPIs(detail){
  setKPI('reportsTotalKpi','—',detail,'bad');setKPI('reportsHighKpi','—',detail,'bad');setKPI('reportsTargetsKpi','—',detail,'bad');setKPI('reportsLatestKpi','—',detail,'bad');
  const visible=$('reportsVisibleCount');if(visible)visible.textContent='—/—';
}

function updateKPIs(items){
  const high=items.filter(item=>['high','critical'].includes(normalizedRisk(item.risk_level))).length;
  const distinct=new Set(items.map(item=>`${lower(item.target_type)}:${text(item.target_id||item.target)}`).filter(value=>!value.endsWith(':'))).size;
  const latest=[...items].sort((a,b)=>Date.parse(b?.created_at||0)-Date.parse(a?.created_at||0))[0];
  setKPI('reportsTotalKpi',String(items.length),items.length?'Durable report records returned by your vault.':'No durable report yet.',items.length?'good':'');
  setKPI('reportsHighKpi',String(high),high?'High/critical reports in the returned history.':'No high/critical report in the returned history.',high?'warn':'good');
  setKPI('reportsTargetsKpi',String(distinct),'Distinct target identifiers represented in the vault.',distinct?'good':'');
  setKPI('reportsLatestKpi',latest?when(latest.created_at):'—',latest?'Newest durable report timestamp.':'No report timestamp available.',latest?'good':'');
}

function render(){
  const host=$('reportsList'),query=lower($('reportsSearch')?.value),riskFilter=lower($('reportsRisk')?.value);
  if(!host)return;
  const filtered=[...reports].filter(item=>{
    const risk=normalizedRisk(item.risk_level),haystack=lower(`${item.target_type||''} ${item.target_id||item.target||''} ${item.request_id||''} ${risk}`);
    return(!riskFilter||risk===riskFilter)&&(!query||haystack.includes(query));
  }).sort((a,b)=>Date.parse(b?.created_at||0)-Date.parse(a?.created_at||0));
  $('reportsVisibleCount').textContent=`${filtered.length}/${reports.length}`;
  if(!filtered.length){host.innerHTML='<div class="ops-empty">No durable report matches the current filters.</div>';return;}
  host.innerHTML=filtered.map(item=>{
    const target=text(item.target_id||item.target),type=text(item.target_type||'target'),risk=normalizedRisk(item.risk_level),score=scoreOf(item),signals=reportSignals(item),floor=signals.structural_floor??signals.structural_floor_score,requestID=text(item.request_id),signed=Boolean(item.signature||item.signed===true||item.final_verdict?.signed===true);
    return`<article class="ops-record"><div class="ops-record-head"><div class="ops-record-title"><span>${esc(type)} · ${requestID?`REQUEST ${esc(short(requestID))}`:'DURABLE REPORT'}</span><b>${esc(target||'Target unavailable')}</b><small>${esc(when(item.created_at))}</small></div><span class="ops-risk ${esc(risk)}">${esc(risk)}</span></div><div class="ops-record-meta"><div><label>Score</label><strong>${score===null?'—':esc(score)}</strong></div><div><label>Structural floor</label><strong>${esc(floor??'—')}</strong></div><div><label>Evidence state</label><strong>${signed?'SIGNED':'DURABLE'}</strong></div><div><label>Target type</label><strong>${esc(type.toUpperCase())}</strong></div></div><div class="ops-record-actions">${target?`<a class="ops-btn primary" href="${scanURL(type,target)}">Re-investigate</a><button class="ops-btn" type="button" data-copy-target="${esc(target)}">Copy target</button>`:''}</div></article>`;
  }).join('');
}

async function copyTarget(value,button){try{await navigator.clipboard.writeText(value);const previous=button.textContent;button.textContent='Copied';setTimeout(()=>button.textContent=previous,900);}catch{status('Clipboard access is unavailable in this browser.','bad');}}

async function load(){
  try{await KoscheiAuth.init();}catch{}
  if(!KoscheiAuth.requireAuth('/login'))return;
  clearStatus();
  const accessResponse=await KoscheiAuth.apiCall('/api/auth/premium-access',{method:'GET'}).catch(()=>null);
  const accessData=accessResponse?await accessResponse.json().catch(()=>({})):{};
  if(!accessResponse?.ok||accessData.access?.active!==true){
    reports=[];setUnavailableKPIs('Report metrics unavailable until holder access is active.');$('reportsList').innerHTML='<div class="ops-empty"><b>KOSCH holder access is required.</b><br>Verify your wallet and official-mint balance before opening durable account reports.</div>';status('Durable report history is account-scoped and requires active KOSCH holder access.','bad');return;
  }
  const response=await KoscheiAuth.apiCall('/api/v1/unified/reports',{method:'GET'}).catch(()=>null);
  const data=response?await response.json().catch(()=>({})):{};
  if(!response?.ok){reports=[];setUnavailableKPIs('Report service unavailable; no count inferred.');$('reportsList').innerHTML='<div class="ops-empty">The report service is unavailable. No report count has been inferred.</div>';status('Report vault unavailable. Existing evidence was not replaced with a synthetic result.','bad');return;}
  reports=arr(data.reports).length?arr(data.reports):arr(obj(data.data).reports);
  updateKPIs(reports);render();
  $('reportsAccess').textContent=`${text(accessData.access?.token_tier||'holder').toUpperCase()} ACCESS`;
}

document.addEventListener('click',event=>{const button=event.target.closest('[data-copy-target]');if(button)copyTarget(button.dataset.copyTarget||'',button);});
$('reportsSearch')?.addEventListener('input',render);$('reportsRisk')?.addEventListener('change',render);$('reportsReload')?.addEventListener('click',load);
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',load);else load();
})();
