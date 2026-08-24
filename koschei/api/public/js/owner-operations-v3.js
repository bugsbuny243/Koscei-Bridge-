(()=>{
'use strict';
if(window.__koscheiOwnerOperationsV3)return;
window.__koscheiOwnerOperationsV3=true;
const ready=fn=>document.readyState==='loading'?document.addEventListener('DOMContentLoaded',fn,{once:true}):fn();
const text=value=>String(value??'').trim();
const lower=value=>text(value).toLowerCase();
const num=value=>Number.isFinite(Number(value))?new Intl.NumberFormat('en-US').format(Number(value)):'—';
const dt=value=>{const parsed=new Date(value||0);return Number.isNaN(parsed.getTime())?'—':new Intl.DateTimeFormat('en-US',{dateStyle:'medium',timeStyle:'short'}).format(parsed)};
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const labels={command:['Overview','Operations overview','Production evidence · SaaS · system health'],arvis:['ARVIS','ARVIS investigations','Evidence-backed investigation operations'],customers:['Customers','Customers & plans','Accounts · SaaS entitlements · identity'],access:['Token telemetry','KOSCH token telemetry','Historical token telemetry · never commercial access'],feedback:['Feedback','Customer feedback','Customer signals and product feedback'],security:['Security','Security events','Audit and security evidence'],system:['System','System health','Production dependencies and controls'],brain:['Assistant','Owner assistant','Explain existing production evidence']};
let overviewRendering=false,customersRendering=false,telemetryRendering=false;
let overviewTimer=0,customersTimer=0,telemetryTimer=0;

async function api(path,opt={}){
  if(window.KoscheiOwner?.api)return window.KoscheiOwner.api(path,opt);
  const headers=new Headers(opt.headers||{});if(opt.body&&!headers.has('Content-Type'))headers.set('Content-Type','application/json');
  const response=await fetch(path,{credentials:'same-origin',...opt,headers});const data=await response.json().catch(()=>({}));
  if(!response.ok||data.ok===false)throw new Error(data.message||data.error||`HTTP ${response.status}`);return data;
}

function currentSection(){return document.querySelector('#desktopNav [data-nav].active')?.dataset.nav||document.querySelector('#mobileNav [data-nav].active')?.dataset.nav||'command'}
function rewriteNavButton(button){
  const entry=labels[button.dataset.nav];if(!entry)return;
  if(button.closest('#desktopNav')){
    const spans=button.querySelectorAll('span');const labelNode=spans[spans.length-1];if(labelNode&&labelNode.textContent!==entry[0])labelNode.textContent=entry[0];
    return;
  }
  if(button.closest('#mobileNav')){
    const textNode=[...button.childNodes].find(node=>node.nodeType===Node.TEXT_NODE&&text(node.nodeValue));
    if(textNode&&text(textNode.nodeValue)!==entry[0])textNode.nodeValue=entry[0];
    else if(!textNode)button.append(document.createTextNode(entry[0]));
  }
}
function rewriteNavigation(){
  document.querySelectorAll('[data-nav]').forEach(rewriteNavButton);
  const active=labels[currentSection()]||labels.command;
  const title=document.getElementById('pageTitle'),eyebrow=document.getElementById('pageEyebrow');
  if(title&&title.textContent!==active[1])title.textContent=active[1];if(eyebrow&&eyebrow.textContent!==active[2])eyebrow.textContent=active[2];
}

function rewriteLogin(){
  const login=document.getElementById('loginView');if(!login)return;
  const small=login.querySelector('.brand small');if(small)small.textContent='Owner Control Center';
  const eyebrow=login.querySelector('.login-copy .eyebrow');if(eyebrow)eyebrow.textContent='Owner only · production access';
  const h1=login.querySelector('.login-copy h1');if(h1)h1.textContent='Production evidence, customers and system health in one control center.';
  const p=login.querySelector('.login-copy p');if(p)p.textContent='Review ARVIS investigations, SaaS entitlements, customer state, security events and service health without turning historical KOSCH telemetry into product authorization.';
}

function serviceLabel(key){return ({database:'Database',neon_auth:'Neon Auth',solana_rpc:'Solana RPC',security_radar:'ARVIS pipeline',visual_renderer:'Report renderer',owner_brain:'Owner assistant'})[key]||key.replaceAll('_',' ')}
function statusOf(raw){return text(typeof raw==='string'?raw:raw?.status||'unknown')||'unknown'}
function planOf(user){const plan=lower(user?.plan_id);return ['starter','professional','enterprise'].includes(plan)?plan:'none'}
function paidActive(user){return lower(user?.active_entitlement_status)==='active'&&planOf(user)!=='none'}

async function renderOverview(){
  const root=document.getElementById('commandContent');if(!root||overviewRendering)return;overviewRendering=true;
  try{
    const [operations,usersResult]=await Promise.allSettled([api('/api/owner/operations'),api('/api/owner/users')]);
    const operationsData=operations.status==='fulfilled'?operations.value:{};
    const users=usersResult.status==='fulfilled'&&Array.isArray(usersResult.value?.users)?usersResult.value.users:null;
    const summary=operationsData.summary||{},radar=operationsData.radar||{},services=operationsData.services||{};
    const activeUsers=users?users.filter(user=>lower(user.status||'active')==='active'):null;
    const activeEntitlements=users?users.filter(paidActive):null;
    const planCount=plan=>activeEntitlements?activeEntitlements.filter(user=>planOf(user)===plan).length:null;
    const serviceEntries=Object.entries(services).filter(([key])=>key!=='kosch_access');
    root.innerHTML=`<div class="owner-v3-overview" data-owner-v3-overview="1">
      <section class="owner-v3-hero"><div><span class="eyebrow">Owner control center</span><h2>See the product as it actually runs.</h2><p>Customer accounts, SaaS authorization, ARVIS evidence and production dependencies are separated here. KOSCH telemetry may remain visible for token history, but it is not a commercial access source.</p></div><div class="owner-v3-status"><span>ARVIS pipeline</span><b>${esc(statusOf(radar.pipeline_status||'unknown'))}</b><span>${radar.background_streams_paused===true?'background streams paused':'runtime state from production'}</span></div></section>
      <section class="owner-v3-kpis">
        <article class="owner-v3-kpi"><span>Total users</span><strong>${num(summary.total_users)}</strong><small>Production account records.</small></article>
        <article class="owner-v3-kpi"><span>Active users</span><strong>${activeUsers?num(activeUsers.length):'—'}</strong><small>${activeUsers?'Current owner user records':'User list unavailable'}.</small></article>
        <article class="owner-v3-kpi"><span>Paid entitlements</span><strong>${activeEntitlements?num(activeEntitlements.length):'—'}</strong><small>Active SaaS authorization only.</small></article>
        <article class="owner-v3-kpi"><span>ARVIS · 24h</span><strong>${num(summary.radar_verdicts_24h)}</strong><small>${num(summary.high_risk_24h)} high / critical signed verdicts.</small></article>
        <article class="owner-v3-kpi"><span>Security · 24h</span><strong>${num(summary.security_events_24h)}</strong><small>Audit/security events.</small></article>
        <article class="owner-v3-kpi"><span>Open feedback</span><strong>${num(summary.open_feedback)}</strong><small>New, reviewing or planned feedback.</small></article>
      </section>
      <section class="owner-v3-grid">
        <article class="owner-v3-panel"><span class="eyebrow">Commercial access</span><h3>SaaS plan distribution</h3><div class="owner-v3-plans"><div class="owner-v3-plan"><span>Starter</span><b>${planCount('starter')===null?'—':num(planCount('starter'))}</b></div><div class="owner-v3-plan"><span>Professional</span><b>${planCount('professional')===null?'—':num(planCount('professional'))}</b></div><div class="owner-v3-plan"><span>Enterprise</span><b>${planCount('enterprise')===null?'—':num(planCount('enterprise'))}</b></div></div><div class="owner-v3-note" style="margin-top:12px">Plans authorize capacity and eligible product surfaces. They do not change ARVIS evidence, grade, policy or confidence.</div></article>
        <article class="owner-v3-panel"><span class="eyebrow">Production dependencies</span><h3>Service health</h3><div class="owner-v3-services">${serviceEntries.map(([key,raw])=>`<div class="owner-v3-service"><span>${esc(serviceLabel(key))}</span><b>${esc(statusOf(raw))}</b></div>`).join('')||'<div class="owner-v3-service"><span>Service data unavailable</span><b>UNAVAILABLE</b></div>'}</div></article>
      </section>
      <nav class="owner-v3-actions" aria-label="Owner quick actions"><a class="owner-v3-action" href="#" data-owner-nav="arvis"><span>Investigate</span><b>Open ARVIS operations →</b></a><a class="owner-v3-action" href="#" data-owner-nav="customers"><span>Accounts</span><b>Review customers & plans →</b></a><a class="owner-v3-action" href="#" data-owner-nav="security"><span>Security</span><b>Review audit events →</b></a><a class="owner-v3-action" href="#" data-owner-nav="system"><span>Runtime</span><b>Inspect service health →</b></a></nav>
    </div>`;
    root.querySelectorAll('[data-owner-nav]').forEach(link=>link.addEventListener('click',event=>{event.preventDefault();document.querySelector(`#desktopNav [data-nav="${link.dataset.ownerNav}"]`)?.click();}));
  }catch(error){root.innerHTML=`<div class="owner-v3-note" data-owner-v3-overview="1">Owner overview unavailable: ${esc(error?.message||'production data could not be loaded')}</div>`}
  finally{overviewRendering=false;rewriteNavigation();}
}

function customerTable(users){
  if(!users.length)return'<div class="empty">No customer account matched this view.</div>';
  return `<div class="table-wrap"><table class="table"><thead><tr><th>Customer</th><th>Wallet</th><th>SaaS plan</th><th>Entitlement</th><th>Account</th><th>Expires</th><th>Action</th></tr></thead><tbody>${users.map(user=>`<tr><td><b>${esc(user.email||'—')}</b><div class="mono">${esc(text(user.auth_subject).slice(0,32)||'—')}</div></td><td class="mono">${esc(text(user.wallet_address).slice(0,22)||'—')}</td><td><span class="badge ${paidActive(user)?'ok':'warn'}">${esc(planOf(user).toUpperCase())}</span></td><td>${esc(text(user.active_entitlement_status)||'inactive')}</td><td>${esc(text(user.status)||'active')}</td><td>${esc(dt(user.entitlement_expires_at))}</td><td><button class="btn small" type="button" data-owner-ban="${esc(user.email||'')}">${lower(user.status)==='banned'?'Unban':'Ban'}</button> <button class="btn small danger" type="button" data-owner-remove="${esc(user.email||'')}">Remove</button></td></tr>`).join('')}</tbody></table></div>`;
}

function bindCustomerActions(root,users){
  root.querySelectorAll('[data-owner-ban]').forEach(button=>button.addEventListener('click',async()=>{
    const email=button.dataset.ownerBan,user=users.find(item=>lower(item.email)===lower(email));if(!email||!user)return;
    const ban=lower(user.status)!=='banned';const reason=prompt(ban?'Reason for ban:':'Reason for unban:','owner_control_center');if(reason===null)return;
    button.disabled=true;try{await api('/api/owner/users/ban',{method:'POST',body:JSON.stringify({email,ban,reason})});await renderCustomers();}catch(error){alert(error.message||'Customer update failed.');}finally{button.disabled=false;}
  }));
  root.querySelectorAll('[data-owner-remove]').forEach(button=>button.addEventListener('click',async()=>{
    const email=button.dataset.ownerRemove;if(!email||!confirm(`Remove ${email} from active product access?`))return;
    button.disabled=true;try{await api('/api/owner/users/remove',{method:'POST',body:JSON.stringify({email,reason:'owner_control_center_removed'})});await renderCustomers();}catch(error){alert(error.message||'Customer removal failed.');}finally{button.disabled=false;}
  }));
}

async function renderCustomers(){
  const root=document.getElementById('customersContent');if(!root||customersRendering)return;customersRendering=true;
  try{
    const data=await api('/api/owner/users'),users=Array.isArray(data.users)?data.users:[];
    const paid=users.filter(paidActive),starter=paid.filter(user=>planOf(user)==='starter').length,professional=paid.filter(user=>planOf(user)==='professional').length,enterprise=paid.filter(user=>planOf(user)==='enterprise').length;
    root.innerHTML=`<div data-owner-customers-v3="1"><section class="owner-v3-hero"><div><span class="eyebrow">Customer operations</span><h2>Accounts and paid access, without token-tier confusion.</h2><p>This view reads the owner customer contract and active SaaS entitlement fields. Wallet links are identity context only; KOSCH balances do not activate, upgrade or discount a plan.</p></div><div class="owner-v3-status"><span>Paid entitlements</span><b>${num(paid.length)}</b><span>Starter ${num(starter)} · Professional ${num(professional)} · Enterprise ${num(enterprise)}</span></div></section><section class="owner-v3-panel"><div class="toolbar"><div><span class="eyebrow">Accounts</span><h3>Customer directory</h3></div><div class="filters"><input class="input" id="ownerCustomerSearchV3" placeholder="Email, auth subject, wallet or plan"></div></div><div id="ownerCustomerTableV3">${customerTable(users)}</div></section></div>`;
    const input=document.getElementById('ownerCustomerSearchV3'),table=document.getElementById('ownerCustomerTableV3');
    const refresh=()=>{const q=lower(input?.value);const filtered=!q?users:users.filter(user=>[user.email,user.auth_subject,user.wallet_address,user.plan_id,user.status,user.active_entitlement_status].some(value=>lower(value).includes(q)));table.innerHTML=customerTable(filtered);bindCustomerActions(table,filtered);};
    input?.addEventListener('input',refresh);bindCustomerActions(table,users);
  }catch(error){root.innerHTML=`<div class="owner-v3-note" data-owner-customers-v3="1">Customer SaaS state unavailable: ${esc(error.message||'owner users could not be loaded')}</div>`}
  finally{customersRendering=false;rewriteNavigation();}
}

function telemetryTable(users){
  if(!users.length)return'<div class="empty">No KOSCH snapshot is currently available.</div>';
  return `<div class="table-wrap"><table class="table"><thead><tr><th>Account</th><th>Wallet</th><th>Observed KOSCH</th><th>Legacy snapshot label</th><th>Checked</th></tr></thead><tbody>${users.map(user=>`<tr><td><b>${esc(user.email||'—')}</b></td><td class="mono">${esc(text(user.wallet_address).slice(0,28)||'—')}</td><td>${esc(text(user.amount)||'0')}</td><td>${esc(text(user.tier)||'none')}</td><td>${esc(dt(user.checked_at||user.created_at))}</td></tr>`).join('')}</tbody></table></div>`;
}

async function renderTokenTelemetry(){
  const root=document.getElementById('accessContent');if(!root||telemetryRendering)return;telemetryRendering=true;
  try{
    const data=await api('/api/owner/kosch-access'),users=Array.isArray(data.users)?data.users:[],summary=data.summary||{};
    root.innerHTML=`<div data-owner-telemetry-v3="1"><section class="owner-v3-hero"><div><span class="eyebrow">Token telemetry</span><h2>KOSCH is telemetry, not product authorization.</h2><p>These records preserve wallet verification and historical token snapshots for observability. They do not unlock routes, quotas, discounts, API credentials, evidence weight or verdict authority.</p></div><div class="owner-v3-status"><span>Observed holders</span><b>${num(summary.holders)}</b><span>read-only legacy snapshot data</span></div></section><section class="owner-v3-panel"><span class="eyebrow">Read-only snapshot</span><h3>Latest token observations</h3><div class="owner-v3-note" style="margin-bottom:12px">Commercial access is controlled only by active Starter, Professional or Enterprise SaaS entitlements. Use Customers & plans for authorization state.</div>${telemetryTable(users)}</section></div>`;
  }catch(error){root.innerHTML=`<div class="owner-v3-note" data-owner-telemetry-v3="1">KOSCH telemetry unavailable: ${esc(error.message||'snapshot source could not be loaded')}</div>`}
  finally{telemetryRendering=false;rewriteNavigation();}
}

function scheduleOverview(){clearTimeout(overviewTimer);overviewTimer=setTimeout(()=>{const root=document.getElementById('commandContent');if(root&&!root.querySelector('[data-owner-v3-overview]'))renderOverview();},80)}
function scheduleCustomers(){clearTimeout(customersTimer);customersTimer=setTimeout(()=>{const root=document.getElementById('customersContent');if(root&&!root.querySelector('[data-owner-customers-v3]'))renderCustomers();},80)}
function scheduleTelemetry(){clearTimeout(telemetryTimer);telemetryTimer=setTimeout(()=>{const root=document.getElementById('accessContent');if(root&&!root.querySelector('[data-owner-telemetry-v3]'))renderTokenTelemetry();},80)}
function scheduleActive(){rewriteNavigation();const section=currentSection();if(section==='command')scheduleOverview();if(section==='customers')scheduleCustomers();if(section==='access')scheduleTelemetry();}

ready(()=>{
  rewriteLogin();scheduleActive();
  document.addEventListener('click',event=>{if(event.target.closest('[data-nav]'))setTimeout(scheduleActive,0)});
  const command=document.getElementById('commandContent');if(command)new MutationObserver(()=>{if(!overviewRendering&&!command.querySelector('[data-owner-v3-overview]'))scheduleOverview();}).observe(command,{childList:true});
  const customers=document.getElementById('customersContent');if(customers)new MutationObserver(()=>{if(currentSection()==='customers'&&!customersRendering&&!customers.querySelector('[data-owner-customers-v3]'))scheduleCustomers();}).observe(customers,{childList:true});
  const access=document.getElementById('accessContent');if(access)new MutationObserver(()=>{if(currentSection()==='access'&&!telemetryRendering&&!access.querySelector('[data-owner-telemetry-v3]'))scheduleTelemetry();}).observe(access,{childList:true});
  const nav=document.getElementById('desktopNav');if(nav)new MutationObserver(()=>setTimeout(rewriteNavigation,0)).observe(nav,{childList:true,subtree:true});
  const mobile=document.getElementById('mobileNav');if(mobile)new MutationObserver(()=>setTimeout(rewriteNavigation,0)).observe(mobile,{childList:true,subtree:true});
});
})();