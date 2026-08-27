(()=>{
'use strict';
if(window.__koscheiCustomerTransactionPreflightV1)return;
window.__koscheiCustomerTransactionPreflightV1=true;

const endpoint='/api/customer/web3/transaction-preflight';
const form=document.getElementById('scanForm');
const submit=document.getElementById('submit');
const transaction=document.getElementById('transaction');
const wallet=document.getElementById('wallet');
const transactionFields=document.getElementById('transactionFields');
const modeSummary=document.getElementById('modeSummary');
const empty=document.getElementById('empty');
const result=document.getElementById('result');
const share=document.getElementById('shareResult');
const openExplorer=document.getElementById('openExplorer');
if(!form||!submit||!transaction||!transactionFields||!empty||!result)return;

const esc=value=>String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const short=value=>{const text=String(value??'').trim();return text.length>28?`${text.slice(0,12)}…${text.slice(-10)}`:text;};
const list=value=>Array.isArray(value)?value:[];
const active=()=>transactionFields.hidden===false;
const actionLabel=value=>({allow:'PASS — DECLARED POLICIES VERIFIED',warn:'REVIEW BEFORE SIGNING',block:'BLOCK — DO NOT SIGN',withhold:'WITHHOLD — EVIDENCE INCOMPLETE'}[String(value||'').toLowerCase()]||'REVIEW REQUIRED');
const actionClass=value=>({allow:'low',warn:'medium',block:'critical',withhold:'medium'}[String(value||'').toLowerCase()]||'medium');

function syncCopy(){
  if(!active())return;
  if(modeSummary)modeSummary.textContent='Professional Transaction Preflight simulates the serialized Solana transaction and validates decoded execution, program routes and available state evidence before signing. Missing required evidence produces WITHHOLD, never a safety claim.';
  submit.textContent='Run Professional Preflight';
}

document.querySelectorAll('[data-scan-mode]').forEach(button=>button.addEventListener('click',()=>queueMicrotask(syncCopy)));
queueMicrotask(syncCopy);

function hideUtilities(){
  if(share)share.hidden=true;
  if(openExplorer)openExplorer.hidden=true;
}
function working(){
  hideUtilities();
  result.hidden=true;
  result.replaceChildren();
  empty.hidden=false;
  empty.innerHTML='<h2>Professional pre-sign validation is running.</h2><p class="sub" style="margin-top:9px">Koschei is collecting simulation and policy evidence. The transaction is not signed or broadcast.</p>';
}
function accessFailure(status,message){
  hideUtilities();
  result.hidden=true;
  result.replaceChildren();
  empty.hidden=false;
  const title=status===401?'Sign in required':status===403?'Professional+ required':status===429?'Transaction Preflight quota reached':'Preflight unavailable';
  const cta=status===403?'<p class="actions" style="margin-top:14px"><a class="btn" href="/pricing">View Professional</a><a class="btn" href="/account">Account & Plan</a></p>':status===401?'<p class="actions" style="margin-top:14px"><a class="btn" href="/login">Sign in</a></p>':'';
  empty.innerHTML=`<h2>${esc(title)}</h2><p class="sub" style="margin-top:9px">${esc(message||'The evidence request could not be completed.')}</p>${cta}<p class="fine">No fallback safety verdict was generated.</p>`;
}
function rows(items,emptyText){
  return items.length?`<ul class="list">${items.map(item=>`<li><code>${esc(item)}</code></li>`).join('')}</ul>`:`<p class="historySummary">${esc(emptyText)}</p>`;
}
function findingText(item){
  if(typeof item==='string')return item;
  const severity=String(item?.severity||'').toUpperCase();
  return `${severity?severity+' · ':''}${item?.title||item?.code||'Finding'}${item?.evidence?': '+item.evidence:''}`;
}
function render(data){
  const action=String(data?.action||'withhold').toLowerCase();
  const program=data?.program_policy||{};
  const intent=data?.intent_policy||{};
  const findings=list(data?.findings).map(findingText);
  const invoked=list(program.invoked);
  const unexpected=list(program.unexpected);
  const blocked=list(program.blocked_invoked);
  const missing=list(program.missing_required);
  const explanation=data?.pre_signing_explanation;
  const explanationText=typeof explanation==='string'?explanation:(explanation?.summary||explanation?.headline||'');
  const evidenceChecks=[
    ['Guard evidence',Boolean(data?.guard_complete)],
    ['Automatic decode',Boolean(data?.automatic_decode_complete)],
    ['Program policy',Boolean(program.complete)],
    ['Declared state policy',Boolean(intent.complete)],
    ['CPI asset flow',Boolean(data?.cpi_asset_flow_complete)],
    ['Authority surface',Boolean(data?.authority_surface_complete)],
    ['Threat history',Boolean(data?.threat_history_complete)]
  ];
  empty.hidden=true;
  result.hidden=false;
  hideUtilities();
  result.innerHTML=`<article data-customer-transaction-preflight-result><div class="resultHead"><div class="grade">TX</div><div><div class="risk">${esc(actionLabel(action))}</div><div class="badge ${esc(actionClass(action))}">${esc(action.toUpperCase())}</div></div></div><p class="sub" style="margin-top:16px">${esc(data?.summary||'Transaction Guard completed the available evidence checks.')}</p><div class="target">Fingerprint · ${esc(data?.transaction_fingerprint||'UNAVAILABLE')}</div><div class="section"><h3>Evidence completeness</h3><div class="public-signal-list">${evidenceChecks.map(([label,complete])=>`<div class="public-signal ${complete?'verified':'arm_pending'}"><span><b>${esc(label)}</b><small>${complete?'VERIFIED':'INCOMPLETE — DOES NOT IMPLY SAFETY'}</small></span><em>${complete?'COMPLETE':'WITHHELD'}</em></div>`).join('')}</div></div><div class="section"><h3>Program route policy</h3><p class="historySummary">${program.complete?'Declared program policy completed.':'Program policy is incomplete or violated.'}</p>${rows(invoked,'No invoked program identifiers were attached.')} ${unexpected.length?`<p class="historySummary">Unexpected programs</p>${rows(unexpected,'')}`:''}${blocked.length?`<p class="historySummary">Blocked programs invoked</p>${rows(blocked,'')}`:''}${missing.length?`<p class="historySummary">Required programs missing</p>${rows(missing,'')}`:''}</div><div class="section"><h3>Security findings</h3>${findings.length?`<ul class="list">${findings.map(item=>`<li>${esc(item)}</li>`).join('')}</ul>`:'<p class="historySummary">No additional finding was attached. This alone is not a safety claim.</p>'}</div>${explanationText?`<div class="section"><h3>Why</h3><p class="historySummary">${esc(explanationText)}</p></div>`:''}<div class="canonical-note">${esc(data?.warning||'Koschei does not sign, submit or custody the transaction.')} Numeric risk scores are not the authority for this Professional result; evidence completeness and policy outcomes are.</div></article>`;
}

form.addEventListener('submit',async event=>{
  if(!active())return;
  event.preventDefault();
  event.stopImmediatePropagation();
  const serialized=transaction.value.trim();
  if(!serialized)return;
  submit.disabled=true;
  submit.textContent='Validating before signing…';
  working();
  try{
    const response=await fetch(endpoint,{
      method:'POST',
      credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({transaction:serialized,encoding:'base64',network:'solana-mainnet',wallet:wallet?.value.trim()||''})
    });
    const data=await response.json().catch(()=>({}));
    if(!response.ok){accessFailure(response.status,data.message||data.error||data.code||`HTTP ${response.status}`);return;}
    render(data);
    transaction.value='';
  }catch(error){
    accessFailure(0,error?.message||'Transaction Preflight evidence service unavailable.');
  }finally{
    submit.disabled=false;
    syncCopy();
  }
},true);
})();
