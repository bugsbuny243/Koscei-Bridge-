(()=>{
'use strict';
if(window.__koscheiCustomerTransactionPreflightV1)return;
window.__koscheiCustomerTransactionPreflightV1=true;

const endpoint='/api/customer/web3/transaction-preflight';
const recheckEndpoint='/api/customer/web3/transaction-state-recheck';
let pendingRecheck=null;
let authLoaderPromise=null;
let authInitPromise=null;
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

async function ensureCustomerAuth(){
  if(window.KoscheiAuth?.apiCall)return window.KoscheiAuth;
  if(!authLoaderPromise){
    authLoaderPromise=new Promise((resolve,reject)=>{
      const script=document.createElement('script');
      script.src='/js/koschei-auth.js?v=33';
      script.async=true;
      script.onload=()=>{
        if(window.KoscheiAuth?.apiCall){resolve(window.KoscheiAuth);return;}
        authLoaderPromise=null;
        reject(new Error('Customer authentication helper unavailable.'));
      };
      script.onerror=()=>{
        authLoaderPromise=null;
        reject(new Error('Customer authentication helper unavailable.'));
      };
      document.head.appendChild(script);
    });
  }
  return authLoaderPromise;
}
async function initializedCustomerAuth(){
  const auth=await ensureCustomerAuth();
  if(!authInitPromise){
    authInitPromise=(async()=>{
      if(typeof auth.init==='function')await auth.init();
      return auth;
    })().catch(error=>{authInitPromise=null;throw error;});
  }
  return authInitPromise;
}
async function customerAPI(path,options){
  const auth=await initializedCustomerAuth();
  const response=await auth.apiCall(path,options);
  if(!response)throw new Error('Customer authentication request unavailable.');
  return response;
}

function hideUtilities(){
  if(share)share.hidden=true;
  if(openExplorer)openExplorer.hidden=true;
}
function clearPendingRecheck(){
  pendingRecheck=null;
}
function invalidateStateRecheckUI(){
  clearPendingRecheck();
  const editor=document.getElementById('stateRecheckTransaction');
  if(editor)editor.value='';
  const button=document.getElementById('stateRecheckRun');
  if(button){button.disabled=true;button.textContent='Run a fresh preflight';}
  result.querySelector('[data-customer-state-recheck]')?.remove();
}
function prepareStateRecheck(data){
  clearPendingRecheck();
  const permit=data?.enforcement_permit;
  const witness=data?.state_witness;
  const action=String(data?.action||'').toLowerCase();
  const permitVersion=String(permit?.version||'');
  const stateBoundPermit=permitVersion==='koschei-transaction-guard-permit-v2'||permitVersion==='koschei-transaction-guard-permit-v3';
  if(action==='allow'&&stateBoundPermit&&data?.enforcement_permit_issued===true&&permit?.token&&data?.state_witness_complete===true&&witness?.complete===true){
    pendingRecheck={permitToken:String(permit.token),network:String(data?.network||'solana-mainnet'),stateWitness:witness,expiresAt:String(permit?.claims?.expires_at||'')};
  }
}
function mountStateRecheck(){
  if(!pendingRecheck)return;
  const article=result.querySelector('[data-customer-transaction-preflight-result]');
  if(!article||article.querySelector('[data-customer-state-recheck]'))return;
  const panel=document.createElement('div');
  panel.className='section';
  panel.dataset.customerStateRecheck='1';
  panel.innerHTML=`<h3>Fresh state recheck before signing</h3><p class="historySummary">A state-bound permit is available. Paste the exact same serialized transaction again immediately before signing. Koschei will re-read only the bounded witnessed account set. The transaction is not signed or broadcast.</p><textarea id="stateRecheckTransaction" class="input mono" rows="5" autocomplete="off" spellcheck="false" placeholder="Paste the same base64 transaction again"></textarea><p class="actions" style="margin-top:12px"><button class="btn" id="stateRecheckRun" type="button">Recheck state now</button></p><p class="fine">Permit expires ${esc(pendingRecheck.expiresAt||'soon')}. Permit and witness remain only in page memory and are cleared after this recheck or when the page closes.</p><div id="stateRecheckResult"></div>`;
  article.appendChild(panel);
  document.getElementById('stateRecheckRun')?.addEventListener('click',runStateRecheck);
}
async function runStateRecheck(){
  const snapshot=pendingRecheck;
  const editor=document.getElementById('stateRecheckTransaction');
  const output=document.getElementById('stateRecheckResult');
  const button=document.getElementById('stateRecheckRun');
  const serialized=editor?.value.trim()||'';
  if(!snapshot||!serialized)return;
  if(button){button.disabled=true;button.textContent='Rechecking witnessed state…';}
  if(output)output.innerHTML='<p class="historySummary">Collecting fresh bounded account-state evidence. No safety claim is made until the server returns a verified decision.</p>';
  try{
    const response=await customerAPI(recheckEndpoint,{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({permit_token:snapshot.permitToken,transaction:serialized,network:snapshot.network,state_witness:snapshot.stateWitness})});
    const data=await response.json().catch(()=>({}));
    const decision=data?.decision||{};
    const safe=response.ok&&data?.ok===true&&data?.safe_to_proceed===true;
    if(output){
      const title=safe?'STATE UNCHANGED — SERVER SAYS SAFE TO PROCEED':'DO NOT RELY ON PRIOR PREFLIGHT';
      const detail=decision?.reason||data?.message||data?.error||data?.code||`HTTP ${response.status}`;
      output.innerHTML=`<div class="public-signal ${safe?'verified':'arm_pending'}"><span><b>${esc(title)}</b><small>${esc(String(decision?.status||data?.code||'state recheck incomplete').toUpperCase())}</small></span><em>${safe?'PROCEED':'WITHHOLD'}</em></div><p class="historySummary" style="margin-top:10px">${esc(detail)}</p>`;
    }
  }catch(error){
    if(output)output.innerHTML=`<div class="public-signal arm_pending"><span><b>STATE RECHECK UNAVAILABLE</b><small>${esc(error?.message||'Fresh state evidence could not be collected.')}</small></span><em>WITHHOLD</em></div>`;
  }finally{
    if(editor)editor.value='';
    if(pendingRecheck===snapshot)clearPendingRecheck();
    if(button){button.disabled=true;button.textContent='State recheck consumed';}
  }
}

function working(){
  clearPendingRecheck();
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
  mountStateRecheck();
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
    const response=await customerAPI(endpoint,{
      method:'POST',
      credentials:'same-origin',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({transaction:serialized,encoding:'base64',network:'solana-mainnet',wallet:wallet?.value.trim()||''})
    });
    const data=await response.json().catch(()=>({}));
    if(!response.ok){accessFailure(response.status,data.message||data.error||data.code||`HTTP ${response.status}`);return;}
    prepareStateRecheck(data);
    render(data);
    transaction.value='';
  }catch(error){
    accessFailure(0,error?.message||'Transaction Preflight evidence service unavailable.');
  }finally{
    submit.disabled=false;
    syncCopy();
  }
},true);
window.addEventListener('pagehide',invalidateStateRecheckUI);
window.addEventListener('pageshow',event=>{if(event.persisted)invalidateStateRecheckUI();});
})();
