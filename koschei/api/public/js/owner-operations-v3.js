(()=>{
'use strict';
if(window.__koscheiOwnerOperationsV3)return;
window.__koscheiOwnerOperationsV3=true;
const ready=fn=>document.readyState==='loading'?document.addEventListener('DOMContentLoaded',fn,{once:true}):fn();
const text=value=>String(value??'').trim();
const num=value=>Number.isFinite(Number(value))?new Intl.NumberFormat('en-US').format(Number(value)):'—';
const esc=value=>String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const labels={command:['Overview','Operations overview','Production evidence · SaaS · system health'],arvis:['ARVIS','ARVIS investigations','Evidence-backed investigation operations'],customers:['Customers','Customers','Accounts · SaaS entitlements · identity'],access:['Token telemetry','KOSCH token telemetry','Historical token telemetry · not commercial access'],feedback:['Feedback','Customer feedback','Customer signals and product feedback'],security:['Security','Security events','Audit and security evidence'],system:['System','System health','Production dependencies and controls'],brain:['Assistant','Owner assistant','Explain existing production evidence']};
let rendering=false,timer=0;

async function api(path){
  if(window.KoscheiOwner?.api)return window.KoscheiOwner.api(path);
  const response=await fetch(path,{credentials:'same-origin'});const data=await response.json().catch(()=>({}));if(!response.ok)throw new Error(data.error||`HTTP ${response.status}`);return data;
}

function currentSection(){return document.querySelector('#desktopNav [data-nav].active')?.dataset.nav||document.querySelector('#mobileNav [data-nav].active')?.dataset.nav||'command'}
function rewriteNavigation(){
  document.querySelectorAll('[data-nav]').forEach(button=>{const entry=labels[button.dataset.nav];if(!entry)return;const spans=button.querySelectorAll('span');if(spans.length)spans[spans.length-1].textContent=entry[0];else button.textContent=entry[0];});
  const active=labels[currentSection()]||labels.command;
  const title=document.getElementById('pageTitle'),eyebrow=document.getElementById('pageEyebrow');if(title)title.textContent=active[1];if(eyebrow)eyebrow.textContent=active[2];
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

async function renderOverview(){
  const root=document.getElementById('commandContent');if(!root||rendering)return;
  rendering=true;
  try{
    const [operations,usersResult]=await Promise.allSettled([api('/api/owner/operations'),api('/api/owner/users')]);
    const operationsData=operations.status==='fulfilled'?operations.value:{};
    const users=usersResult.status==='fulfilled'&&Array.isArray(usersResult.value?.users)?usersResult.value.users:null;
    const summary=operationsData.summary||{},radar=operationsData.radar||{},services=operationsData.services||{};
    const activeUsers=users?users.filter(user=>text(user.status||'active').toLowerCase()==='active'):null;
    const activeEntitlements=users?users.filter(user=>text(user.active_entitlement_status).toLowerCase()==='active'):null;
    const planCount=plan=>activeEntitlements?activeEntitlements.filter(user=>text(user.plan_id).toLowerCase()===plan).length:null;
    const serviceEntries=Object.entries(services).filter(([key])=>key!=='kosch_access');
    root.innerHTML=`<div class="owner-v3-overview" data-owner-v3-overview="1">
      <section class="owner-v3-hero"><div><span class="eyebrow">Owner control center</span><h2>See the product as it actually runs.</h2><p>Customer accounts, SaaS authorization, ARVIS evidence and production dependencies are separated here. KOSCH telemetry may remain visible for token history, but it is not a commercial access source.</p></div><div class="owner-v3-status"><span>ARVIS pipeline</span><b>${esc(statusOf(radar.pipeline_status||'unknown'))}</b><span>${radar.background_streams_paused===true?'background streams paused':'runtime state from production'}</span></div></section>
      <section class="owner-v3-kpis">
        <article class="owner-v3-kpi"><span>Total users</span><strong>${num(summary.total_users)}</strong><small>Production account records.</small></article>
        <article class="owner-v3-kpi"><span>Active users</span><strong>${activeUsers?num(activeUsers.length):'—'}</strong><small>${activeUsers?'Owner user records':'User list unavailable'}.</small></article>
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
    root.querySelectorAll('[data-owner-nav]').forEach(link=>link.addEventListener('click',event=>{event.preventDefault();document.querySelector(`[data-nav="${link.dataset.ownerNav}"]`)?.click();}));
  }catch(error){root.innerHTML=`<div class="owner-v3-note" data-owner-v3-overview="1">Owner overview unavailable: ${esc(error?.message||'production data could not be loaded')}</div>`}
  finally{rendering=false;rewriteNavigation();}
}

function scheduleOverview(){clearTimeout(timer);timer=setTimeout(()=>{const root=document.getElementById('commandContent');if(root&&!root.querySelector('[data-owner-v3-overview]'))renderOverview();},80)}

ready(()=>{
  rewriteLogin();rewriteNavigation();scheduleOverview();
  document.addEventListener('click',event=>{if(event.target.closest('[data-nav]'))setTimeout(()=>{rewriteNavigation();if(currentSection()==='command')scheduleOverview();},0)});
  const command=document.getElementById('commandContent');if(command)new MutationObserver(()=>{if(!rendering&&!command.querySelector('[data-owner-v3-overview]'))scheduleOverview();}).observe(command,{childList:true});
  const nav=document.getElementById('desktopNav');if(nav)new MutationObserver(rewriteNavigation).observe(nav,{childList:true,subtree:true});
});
})();