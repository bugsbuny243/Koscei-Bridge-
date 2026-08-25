(()=>{
'use strict';
if(window.__koscheiPiArvisScanRouter)return;
window.__koscheiPiArvisScanRouter=true;

const esc=value=>String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const isPiAccount=value=>/^G[A-Z2-7]{55}$/.test(String(value||'').trim());
function parsePiTarget(value){
  const raw=String(value||'').trim();
  if(isPiAccount(raw))return{raw,kind:'account',account:raw};
  const parts=raw.split(':');
  if(parts.length===2&&/^[A-Za-z0-9]{1,12}$/.test(parts[0])&&isPiAccount(parts[1]))return{raw,kind:'asset',assetCode:parts[0],issuer:parts[1]};
  return null;
}
function selectedNetwork(){return /testnet/i.test(new URLSearchParams(location.search||'').get('network')||'')?'pi-testnet':'pi-mainnet'}
function stateOf(arm){
  const raw=String(arm?.signals?.evidence_status||arm?.risk_level||'insufficient_evidence').toLowerCase();
  if(raw==='evidence_only')return'observed';
  if(raw==='unknown')return'insufficient_evidence';
  return raw;
}
function stateLabel(state){return({verified:'VERIFIED',observed:'OBSERVED',partial_observation:'PARTIAL OBSERVATION',not_applicable:'NOT APPLICABLE',arm_pending:'EVIDENCE MISSING',insufficient_evidence:'INSUFFICIENT EVIDENCE',window_open:'MONITORING WINDOW'}[state]||String(state||'').toUpperCase())}
function horizonURL(parsed,network){
  const base=network==='pi-testnet'?'https://api.testnet.minepi.com':'https://api.mainnet.minepi.com';
  return parsed.kind==='account'?`${base}/accounts/${encodeURIComponent(parsed.account)}`:`${base}/assets?asset_code=${encodeURIComponent(parsed.assetCode)}&asset_issuer=${encodeURIComponent(parsed.issuer)}`;
}
function renderPi(data,parsed){
  const empty=document.getElementById('empty'),result=document.getElementById('result'),share=document.getElementById('shareResult'),explorer=document.getElementById('openExplorer');
  if(!result)return;
  const report=data?.investigation_report||{},arms=Array.isArray(data?.arms)?data.arms:(Array.isArray(report.evidence_arms)?report.evidence_arms:[]);
  const network=data?.network||report.network||selectedNetwork();
  const label=data?.network_label||report.network_label||(network==='pi-testnet'?'Pi Testnet':'Pi Mainnet');
  const provider=data?.provider||report.provider||'Pi Horizon';
  const observed=Number(data?.observed_arm_count||arms.filter(arm=>['observed','verified'].includes(stateOf(arm))).length||0);
  const final=data?.final_verdict||report.final_verdict||{};
  const rows=arms.map(arm=>{
    const state=stateOf(arm),evidence=Array.isArray(arm.evidence)?arm.evidence:[];
    return `<div class="public-signal ${esc(state)}"><span><b>${esc(arm.module||arm.module_id||'Pi evidence arm')}</b><small>${esc(stateLabel(state))}</small>${evidence[0]?`<small>${esc(evidence[0])}</small>`:''}</span><em>${evidence.length?`${evidence.length} evidence row${evidence.length===1?'':'s'}`:esc(stateLabel(state))}</em></div>`;
  }).join('');
  const details=arms.filter(arm=>Array.isArray(arm.evidence)&&arm.evidence.length).map(arm=>`<details class="section"><summary><strong>${esc(arm.module||arm.module_id)}</strong></summary><ul class="list">${arm.evidence.slice(0,10).map(item=>`<li>${esc(item)}</li>`).join('')}</ul></details>`).join('');
  if(empty)empty.hidden=true;
  result.hidden=false;
  result.innerHTML=`<article class="public-investigation-card"><div class="resultHead"><div class="grade">PI</div><div><div class="risk">${esc(label)} · EVIDENCE REVIEW</div><div class="badge medium">UNSIGNED · RISK UNKNOWN</div></div></div><p class="sub" style="margin-top:16px">${esc(data?.message||'Pi evidence collected. Missing evidence remains unresolved.')}</p><div class="target">${esc(parsed.raw)}</div><div class="verdictMeta" data-signed="false">Provider ${esc(provider)} · observed arms ${esc(observed)}/14 · ruleset ${esc(final.rule_version||'pi-evidence')}</div><div class="section"><h3>Pi evidence coverage</h3><p class="historySummary">ARVIS detected a Pi ${esc(parsed.kind)} target. Solana-only program evidence is never reinterpreted as a Pi finding.</p><div class="public-signal-list">${rows||'<div class="public-signal"><span><b>No Pi evidence arm was attached.</b></span></div>'}</div></div>${details}<div class="canonical-note">No signed Pi risk grade is emitted until the Pi-specific deterministic ruleset has a validated regression corpus. UNKNOWN never becomes SAFE.</div></article>`;
  if(explorer){explorer.hidden=false;explorer.textContent='Open Pi Horizon evidence';explorer.href=horizonURL(parsed,network)}
  if(share)share.hidden=true;
  const params=new URLSearchParams({mode:'token',target:parsed.raw,network});
  history.replaceState({},'',`/scan?${params.toString()}`);
}
function renderFailure(error){
  const empty=document.getElementById('empty'),result=document.getElementById('result');
  if(result){result.hidden=true;result.innerHTML=''}
  if(empty){empty.hidden=false;empty.innerHTML=`<h2>PI EVIDENCE UNAVAILABLE</h2><p class="sub" style="margin-top:9px">ARVIS could not complete the Pi evidence request. The target is not treated as safe.</p><p class="fine">${esc(error?.message||'Pi evidence dependency unavailable.')}</p>`}
}
async function runPiScan(parsed){
  const submit=document.getElementById('submit'),empty=document.getElementById('empty'),result=document.getElementById('result');
  if(submit){submit.disabled=true;submit.textContent='Collecting Pi evidence…'}
  if(result){result.hidden=true;result.innerHTML=''}
  if(empty){empty.hidden=false;empty.innerHTML='<h2>Pi ARVIS investigation is running</h2><p class="sub" style="margin-top:9px">Collecting read-only Horizon, issuer, distribution, liquidity and provenance evidence.</p>'}
  const network=selectedNetwork();
  const controller=new AbortController(),timer=setTimeout(()=>controller.abort(),125000);
  try{
    const response=await fetch('/api/security/radar/check',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:parsed.raw,network,mode:'pi_customer_investigation'}),signal:controller.signal});
    const data=await response.json().catch(()=>({}));
    if(!response.ok)throw new Error(data.message||data.error||`HTTP ${response.status}`);
    renderPi(data,parsed);
  }catch(error){renderFailure(error?.name==='AbortError'?new Error('Pi evidence service timed out after 125 seconds.'):error)}
  finally{clearTimeout(timer);if(submit){submit.disabled=false;submit.textContent='Run Token Investigation'}}
}

const query=new URLSearchParams(location.search||'');
const pathTarget=location.pathname.startsWith('/scan/')?decodeURIComponent(location.pathname.slice(6).split('/')[0]||''):'';
const initialRaw=pathTarget||query.get('target')||query.get('mint')||'';
const initialPi=parsePiTarget(initialRaw);
if(initialPi){
  const preservedNetwork=selectedNetwork();
  history.replaceState({},'',`/scan?mode=token&network=${encodeURIComponent(preservedNetwork)}`);
  setTimeout(()=>{
    const input=document.getElementById('target');if(input)input.value=initialPi.raw;
    runPiScan(initialPi);
  },0);
}

const form=document.getElementById('scanForm');
if(form){
  form.addEventListener('submit',event=>{
    const transactionFields=document.getElementById('transactionFields');
    if(transactionFields&&!transactionFields.hidden)return;
    const parsed=parsePiTarget(document.getElementById('target')?.value||'');
    if(!parsed)return;
    event.preventDefault();
    event.stopImmediatePropagation();
    runPiScan(parsed);
  },true);
}
})();
