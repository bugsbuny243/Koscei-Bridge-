(()=>{
'use strict';
function installScanViewContract(){
  if(!document.querySelector('style[data-koschei-scan-view-contract]')){
    const style=document.createElement('style');
    style.dataset.koscheiScanViewContract='1';
    style.textContent='[hidden]{display:none!important}.modebar .mode{display:block!important;text-align:left!important}.modebar .mode span,.modebar .mode small{display:block}.modebar .mode small{margin-top:4px}';
    document.head.appendChild(style);
  }
  if(!window.__koscheiUnifiedScanNavigation&&!document.querySelector('script[data-koschei-unified-scan-navigation]')){
    const script=document.createElement('script');
    script.src='/js/unified-scan-navigation.js?v=1';
    script.dataset.koscheiUnifiedScanNavigation='1';
    document.head.appendChild(script);
  }
}
installScanViewContract();
const OFFICIAL_KOSCH_MINT='HHPpU9u56Bwxov12nf7DXUCuv6h1q5j1xgGS3yukpump';
const MODES={
  quick:{summary:'Run a fast preflight for a token, wallet, site, or transaction intent. Holder, liquidity, and deep graph coverage may remain unresolved.',button:'Run Quick Check'},
  token:{summary:'Collect the complete token evidence file: authority state, owner-resolved distribution, launch context, graph relations, liquidity, and explicit evidence limits.',button:'Run Token Investigation'},
  transaction:{summary:'Simulate a base64 serialized Solana transaction before signing. Koschei never signs, broadcasts, or requests wallet custody.',button:'Simulate Transaction'},
  deep:{summary:'Run maximum available evidence coverage. Token targets receive the complete technical file; non-token targets remain fail-closed when deep collectors are unavailable.',button:'Run Deep Radar'}
};
const $=id=>document.getElementById(id);
const esc=value=>String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const form=$('scanForm'),submit=$('submit'),target=$('target'),kind=$('kind'),kindLabel=$('kindLabel'),note=$('note'),transaction=$('transaction'),wallet=$('wallet'),targetFields=$('targetFields'),transactionFields=$('transactionFields'),modeSummary=$('modeSummary'),empty=$('empty'),result=$('result'),share=$('shareResult'),openExplorer=$('openExplorer');
const requestGuard=window.KoscheiPublicScanGuard;
let activeMode='token';
let lastSharePayload={};
const clamp=n=>Math.max(0,Math.min(100,Math.round(Number(n)||0)));
const level=r=>r>=85?'critical':r>=65?'high':r>=35?'medium':'low';
const short=value=>{const text=String(value??'');return text.length>24?`${text.slice(0,10)}…${text.slice(-8)}`:text};

async function fetchJSON(url,options={}){
  const timeoutMs=url.includes('/api/token/scan')?45000:url.includes('/api/public/transaction-simulate')?30000:15000;
  const controller=new AbortController();
  const externalSignal=options.signal;
  let timedOut=false;
  const onExternalAbort=()=>controller.abort(externalSignal?.reason);
  if(externalSignal){if(externalSignal.aborted)onExternalAbort();else externalSignal.addEventListener('abort',onExternalAbort,{once:true})}
  const timer=setTimeout(()=>{timedOut=true;controller.abort('koschei_api_timeout')},timeoutMs);
  try{
    const response=await fetch(url,{...options,signal:controller.signal});
    const data=await response.json().catch(()=>({}));
    if(!response.ok)throw new Error(data.error||data.message||data.code||`HTTP ${response.status}`);
    return data;
  }catch(error){
    if(timedOut||error?.name==='AbortError')throw new Error(`The evidence service did not respond within ${timeoutMs/1000} seconds.`);
    throw error;
  }finally{
    clearTimeout(timer);
    if(externalSignal)externalSignal.removeEventListener('abort',onExternalAbort);
  }
}

function stateLabel(state){return({verified:'VERIFIED',observed:'OBSERVED',window_open:'MONITORING WINDOW',not_applicable:'NOT APPLICABLE',arm_pending:'EVIDENCE ARM MISSING'}[state]||String(state||'').toUpperCase())}
function refChip(type,value){const raw=String(value??'').trim();if(!raw)return'';return`<button class="evidence-ref" type="button" data-copy-ref="${esc(raw)}" title="Copy ${esc(type)}"><span>${esc(type)}</span><b>${esc(short(raw))}</b></button>`}
function renderRefs(refs={}){const chips=[];(Array.isArray(refs.wallets)?refs.wallets:[]).forEach(value=>chips.push(refChip('wallet',value)));(Array.isArray(refs.accounts)?refs.accounts:[]).forEach(value=>chips.push(refChip('account',value)));(Array.isArray(refs.signatures)?refs.signatures:[]).forEach(value=>chips.push(refChip('signature',value)));(Array.isArray(refs.slots)?refs.slots:[]).forEach(value=>chips.push(refChip('slot',value)));(Array.isArray(refs.evidence_keys)?refs.evidence_keys:[]).forEach(value=>chips.push(refChip('evidence',value)));return chips.length?`<div class="evidence-refs" aria-label="Evidence references">${chips.join('')}</div>`:''}
function signalRows(rows){return rows.map(row=>`<div class="public-signal ${esc(row.state)}" id="evidence-${esc(row.id)}"><span><b>${esc(row.label)}</b><small>${esc(stateLabel(row.state))}</small>${row.detail?`<small>${esc(row.detail)}</small>`:''}</span><em>${esc(row.value)}</em>${renderRefs(row.refs)}</div>`).join('')}

function setSharePayload(payload){lastSharePayload=payload||{};share.hidden=!lastSharePayload.target;share.textContent='Share on X'}
function resetResult(){result.hidden=true;result.innerHTML='';share.hidden=true;openExplorer.hidden=true;lastSharePayload={}}
function renderWorking(title,copy){empty.hidden=false;empty.innerHTML=`<h2>${esc(title)}</h2><p class="sub" style="margin-top:9px">${esc(copy)}</p>`;resetResult()}
function renderFailure(title,error){empty.hidden=false;empty.innerHTML=`<h2>DEGRADED DEPENDENCY — ${esc(title)}</h2><p class="sub" style="margin-top:9px">Verified evidence could not be completed. This target is not considered safe.</p><p class="fine">${esc(error?.message||'Evidence dependency unavailable.')}</p>`;resetResult()}

function renderTechnicalReport(report,mint){
  if(!report||!window.KoscheiVerdictCard)return false;
  const vm=window.KoscheiVerdictCard.mapVerdictCard(report,{lang:'en'}),h=vm.header;
  const checklist=Array.isArray(vm.checklist)?vm.checklist:[];
  const pending=checklist.filter(row=>['arm_pending','window_open'].includes(row.state));
  const resolved=checklist.filter(row=>!['arm_pending','window_open'].includes(row.state));
  const lpHTML=window.KoscheiLPControlCard?.render(report,{lang:'en'})||'';
  const liveHTML=window.KoscheiLiveEvidenceCard?.render(report,{lang:'en'})||'';
  empty.hidden=true;result.hidden=false;
  result.innerHTML=`<article class="public-investigation-card"><div class="resultHead"><div class="grade">${esc(h.grade||h.icon||'✓')}</div><div><div class="risk">${esc(h.title)}</div><div class="badge medium">SIGNED TECHNICAL REPORT</div></div></div><p class="sub" style="margin-top:16px">${esc(h.copy)}</p><div class="target">${esc(report.target||mint)}</div><div class="verdictMeta" data-signed="${h.signature_short?'true':'false'}">Ruleset ${esc(h.ruleset_version)} · signature ${esc(h.signature_short||'pending')} · ${esc(h.generated_at||'')}</div><div class="official" ${mint===OFFICIAL_KOSCH_MINT?'':'hidden'}><strong>Official KOSCH mint matched.</strong><br>This label verifies asset identity only.</div><div class="section"><h3>Evidence coverage</h3><p class="historySummary">${esc(vm.coverage.text)}</p></div><div class="section"><h3>Verified, observed, and not-applicable signals</h3><div class="public-signal-list">${signalRows(resolved)||'<div class="public-signal"><span><b>No completed signal was attached.</b></span></div>'}</div></div>${pending.length?`<div class="section"><h3>Pending evidence arms and monitoring windows (${pending.length})</h3><p class="historySummary">These rows do not upgrade the verdict to safety. They expose unfinished or time-bounded evidence.</p><div class="public-signal-list">${signalRows(pending)}</div></div>`:''}<div class="section"><h3>${esc(vm.leverage_title)}</h3>${vm.leverage.length?`<ul class="list">${vm.leverage.map(row=>`<li>${esc(row.text)}</li>`).join('')}</ul>`:'<p class="historySummary">No verified active-control row was observed. This does not mean risk-free.</p>'}</div><p class="fine">${esc(vm.disclaimer)}</p></article>${lpHTML}${liveHTML}`;
  const finalVerdict=report.final_verdict||{};
  const modeQuery=activeMode==='deep'?'?mode=deep':'';
  const publicURL=window.KoscheiInvestigationShare?.publicResultURL(report.target||mint,'token')||`${location.origin}/scan/${encodeURIComponent(report.target||mint)}${modeQuery}`;
  setSharePayload({target:report.target||mint,kind:'token',url:publicURL,status:finalVerdict.signed?'ready':'evidence_pending',final_verdict:finalVerdict,grade:h.grade,signature:finalVerdict.signature});
  openExplorer.hidden=false;openExplorer.href=`https://solscan.io/token/${encodeURIComponent(mint)}`;
  history.replaceState({},'',`/scan/${encodeURIComponent(mint)}${modeQuery}`);
  return true;
}

function renderPreflight(data,value){
  const risk=clamp(data.score??data.risk_index),limited=Boolean(data.coverage_warning),missing=Array.isArray(data.not_checked)?data.not_checked:[];
  empty.hidden=true;result.hidden=false;
  result.innerHTML=`<article><div class="resultHead"><div class="grade">FAST</div><div><div class="risk">QUICK PREFLIGHT · ${esc(risk)}/100</div><div class="badge ${limited?'medium':esc(level(risk))}">${esc(String(data.decision||data.policy||'review').toUpperCase())}</div></div></div><p class="sub" style="margin-top:16px">${esc(data.human_message||data.verdict||'Preflight completed.')}</p><div class="target">${esc(value)}</div>${limited?`<div class="section"><h3>Coverage boundary</h3><p class="historySummary">${esc(data.coverage_warning)}</p>${missing.length?`<ul class="list">${missing.map(item=>`<li>${esc(item)}</li>`).join('')}</ul>`:''}</div>`:''}<div class="section"><h3>Observed reasons</h3><ul class="list">${(Array.isArray(data.reasons)?data.reasons:[]).slice(0,8).map(item=>`<li>${esc(item)}</li>`).join('')||'<li>No additional preflight reason was attached.</li>'}</ul></div><div class="canonical-note">Quick Check is a fast preflight. Holder and liquidity evidence were not evaluated unless explicitly attached. Missing evidence = no safety decision.</div></article>`;
  const publicURL=window.KoscheiInvestigationShare?.publicResultURL(value,kind.value)||`${location.origin}/scan?mode=quick&target=${encodeURIComponent(value)}&kind=${encodeURIComponent(kind.value)}`;
  setSharePayload({target:value,kind:kind.value,url:publicURL,status:limited?'evidence_pending':'preflight',decision:data.decision,score:risk,risk_level:level(risk)});
  openExplorer.hidden=true;
}

function findingText(item){if(typeof item==='string')return item;return `${String(item?.severity||'').toUpperCase()}${item?.severity?' · ':''}${item?.title||item?.code||'Finding'}${item?.evidence?`: ${item.evidence}`:''}`}
function actionLabel(value){return({allow:'REVIEW COMPLETE',warn:'REVIEW BEFORE SIGNING',block:'DO NOT SIGN',withhold:'VERDICT WITHHELD'}[String(value||'').toLowerCase()]||'REVIEW')}
function renderTransaction(data){
  const risk=clamp(data.risk_index),riskLevel=String(data.risk_level||level(risk)).toLowerCase();
  const findings=Array.isArray(data.findings)&&data.findings.length?data.findings.map(findingText):['No high-confidence dangerous instruction signal was attached.'];
  const programs=Array.isArray(data.program_ids)&&data.program_ids.length?data.program_ids:['Program identifiers could not be resolved from simulation logs.'];
  const units=data.simulation&&Number.isFinite(Number(data.simulation.units_consumed))?Number(data.simulation.units_consumed).toLocaleString('en-US'):'UNVERIFIED';
  empty.hidden=true;result.hidden=false;share.hidden=true;openExplorer.hidden=true;lastSharePayload={};
  result.innerHTML=`<article><div class="resultHead"><div class="grade">TX</div><div><div class="risk">${esc(actionLabel(data.action))}</div><div class="badge ${esc(riskLevel)}">RISK ${esc(risk)}/100</div></div></div><p class="sub" style="margin-top:16px">${esc(data.summary||'Read-only transaction simulation completed.')}</p><div class="tx-stats"><div class="tx-stat"><span>Compute units</span><b>${esc(units)}</b></div><div class="tx-stat"><span>Programs</span><b>${esc(programs.length)}</b></div><div class="tx-stat"><span>Fingerprint</span><b>${esc(short(data.transaction_fingerprint||'UNAVAILABLE'))}</b></div></div><div class="section"><h3>Security findings</h3><ul class="list">${findings.map(item=>`<li>${esc(item)}</li>`).join('')}</ul></div><div class="section"><h3>Invoked programs</h3><ul class="list">${programs.map(item=>`<li><code>${esc(item)}</code></li>`).join('')}</ul></div><div class="section"><h3>Transaction fingerprint</h3><p class="target">${esc(data.transaction_fingerprint||'UNAVAILABLE')}</p></div><div class="canonical-note">${esc(data.warning||'Read-only shadow mode. The transaction was not signed or broadcast.')}</div></article>`;
}

function canonicalMode(value){return Object.prototype.hasOwnProperty.call(MODES,value)?value:'token'}
function updateModeURL(){
  const query=new URLSearchParams();query.set('mode',activeMode);
  if(activeMode!=='transaction'&&target.value.trim())query.set('target',target.value.trim());
  if(activeMode==='quick'||activeMode==='deep')query.set('kind',kind.value);
  history.replaceState({},'',`/scan?${query.toString()}`);
}
function applyMode(next,{updateURL=false,reset=true}={}){
  activeMode=canonicalMode(next);
  document.querySelectorAll('[data-scan-mode]').forEach(button=>button.setAttribute('aria-pressed',String(button.dataset.scanMode===activeMode)));
  const isTransaction=activeMode==='transaction';
  targetFields.hidden=isTransaction;transactionFields.hidden=!isTransaction;
  target.required=!isTransaction;transaction.required=isTransaction;
  kind.disabled=activeMode==='token';kindLabel.hidden=activeMode==='token';
  if(activeMode==='token')kind.value='token';
  modeSummary.textContent=MODES[activeMode].summary;submit.textContent=MODES[activeMode].button;
  if(reset){empty.hidden=false;empty.innerHTML='<h2>Evidence coverage and all attached ARVIS results appear here.</h2><p class="sub" style="margin-top:9px">Select a mode, provide the required target, and run the canonical investigation workflow.</p>';resetResult()}
  if(updateURL)updateModeURL();
}

async function runTransaction(){
  const serialized=transaction.value.trim();if(!serialized)return;
  submit.disabled=true;submit.textContent='Simulating on Solana…';
  renderWorking('Transaction simulation is running','The serialized transaction is simulated read-only. It is not signed or broadcast.');
  try{
    const data=await fetchJSON('/api/public/transaction-simulate',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({transaction:serialized,encoding:'base64',network:'solana-mainnet',wallet:wallet.value.trim()})});
    renderTransaction(data);
  }catch(error){renderFailure('no transaction simulation result',error)}
  finally{submit.disabled=false;submit.textContent=MODES[activeMode].button}
}

async function runTargetScan(){
  const value=target.value.trim();if(!value)return;
  const tokenScan=activeMode==='token'||(activeMode==='deep'&&kind.value==='token');
  const requestToken=tokenScan&&requestGuard?requestGuard.begin(result,value):null;
  submit.disabled=true;submit.textContent=tokenScan?'Collecting complete evidence…':'Running preflight…';
  renderWorking(tokenScan?'Technical investigation is running':'Quick preflight is running',tokenScan?'Collector results, holder resolution, live windows, launch context, and market evidence are being assembled.':'ARVIS is evaluating the target against the fast preflight evidence boundary.');
  try{
    if(tokenScan){
      const data=await fetchJSON('/api/token/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mint:value,network:'solana-mainnet'})});
      const report=data.investigation_report;
      const decision=requestToken?requestGuard.accept(requestToken,report):{accepted:true};
      if(!decision.accepted){if(decision.reason==='stale_response')return;throw new Error(`scan_target_mismatch:${decision.expected}:${decision.returned}`)}
      if(!renderTechnicalReport(report,value))throw new Error('investigation_report_missing');
    }else{
      const intent=[activeMode==='deep'?'deep_radar_requested':'quick_check',note.value.trim()].filter(Boolean).join(': ');
      const data=await fetchJSON('/api/arvis/preflight',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:value,kind:kind.value,intent,note:note.value.trim()})});
      renderPreflight(data,value);
    }
  }catch(error){
    if(requestToken&&requestGuard&&!requestGuard.isActive(requestToken))return;
    const mismatch=String(error?.message||'').startsWith('scan_target_mismatch:');
    renderFailure(mismatch?'scan target mismatch':'no technical result',mismatch?new Error('A stale or different target result was rejected.'):error);
  }finally{
    const ownsUI=!requestToken||!requestGuard||requestGuard.isActive(requestToken);
    if(requestToken&&requestGuard)requestGuard.finish(requestToken);
    if(ownsUI){submit.disabled=false;submit.textContent=MODES[activeMode].button}
  }
}

async function runScan(){if(activeMode==='transaction')return runTransaction();return runTargetScan()}
form.addEventListener('submit',event=>{event.preventDefault();runScan()});
document.querySelectorAll('[data-scan-mode]').forEach(button=>button.addEventListener('click',()=>applyMode(button.dataset.scanMode,{updateURL:true,reset:true})));
result.addEventListener('click',async event=>{const button=event.target.closest('[data-copy-ref]');if(!button)return;try{await navigator.clipboard.writeText(button.dataset.copyRef||'');const previous=button.innerHTML;button.textContent='Copied';setTimeout(()=>{button.innerHTML=previous},900)}catch{}});
share.addEventListener('click',async()=>{try{if(window.KoscheiInvestigationShare){window.KoscheiInvestigationShare.open(lastSharePayload);return}const url=lastSharePayload.url||location.href;if(navigator.share)await navigator.share({title:'Koschei ARVIS technical investigation',text:'Koschei ARVIS evidence result',url});else{await navigator.clipboard.writeText(url);share.textContent='Link copied'}}catch{}});

const params=new URLSearchParams(location.search);
const pathMint=location.pathname.startsWith('/scan/')?decodeURIComponent(location.pathname.slice(6).split('/')[0]||''):'';
const initialMode=canonicalMode(params.get('mode')||(pathMint?'token':'token'));
const initialKind=params.get('kind')||'token';
applyMode(initialMode,{updateURL:false,reset:false});
if(['token','wallet','site','transaction'].includes(initialKind)&&activeMode!=='token')kind.value=initialKind;
const initial=pathMint||params.get('mint')||params.get('target')||'';
if(initial&&activeMode!=='transaction'){target.value=initial;runScan()}
})();
