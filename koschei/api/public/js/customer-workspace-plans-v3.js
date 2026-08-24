(()=>{
'use strict';
if(window.__koscheiCustomerWorkspacePlansV3)return;
window.__koscheiCustomerWorkspacePlansV3=true;
const ready=fn=>document.readyState==='loading'?document.addEventListener('DOMContentLoaded',fn,{once:true}):fn();
const text=value=>String(value??'').trim();
const planRank={none:0,starter:1,professional:2,enterprise:3};

function capability(title,copy,state='available'){
  const article=document.createElement('article');article.className='workspace-capability';article.dataset.state=state;
  article.innerHTML=`<b>${title}</b><span>${copy}</span>`;return article;
}

function normalizedPlan(value){const raw=text(value).toLowerCase();return Object.prototype.hasOwnProperty.call(planRank,raw)?raw:'none'}
function available(plan,required){return planRank[plan]>=planRank[required]}
function planLabel(plan){return plan==='professional'?'Professional':plan==='enterprise'?'Enterprise':plan==='starter'?'Starter':'No active plan'}

async function loadAccess(){
  try{
    await window.KoscheiAuth?.init?.();
    if(!window.KoscheiAuth?.isLoggedIn?.())return {plan:'none',active:false,signedOut:true};
    const response=await window.KoscheiAuth.apiCall('/api/auth/premium-access',{method:'GET'});
    const data=await response.json().catch(()=>({}));
    const access=data?.access||{};
    return {plan:normalizedPlan(access.plan),active:response.ok&&access.active===true,signedOut:false,remaining:access.outputs_remaining,total:access.outputs_total};
  }catch{return {plan:'none',active:false,signedOut:false,unavailable:true}}
}

function gateLink(link,required,plan,label){
  if(!link)return;
  link.dataset.requiredPlan=required;
  if(available(plan,required))return;
  link.dataset.planState='locked';
  link.href='/pricing';
  link.title=`${label} requires ${required==='professional'?'Professional':'Enterprise'} access`;
}

function annotateWorkspace(plan){
  document.querySelectorAll('.workspace-quick-action').forEach(link=>{
    const href=new URL(link.href,location.origin).pathname;
    if(href==='/watchlist')gateLink(link,'professional',plan,'Watchlist and alerts');
    if(href==='/scan')gateLink(link,'starter',plan,'Account investigation');
  });

  const cards=[...document.querySelectorAll('.workspace-grid .workspace-card')];
  if(cards[0]){
    cards[0].dataset.requiredPlan='starter';
    cards[0].dataset.planState=available(plan,'starter')?'available':'locked';
    if(!available(plan,'starter'))cards[0].querySelectorAll('a[href="/reports"]').forEach(link=>{link.href='/pricing';link.textContent='View Starter';});
  }
  if(cards[1]){
    cards[1].dataset.planState='available';
  }
  if(cards[2]){
    cards[2].dataset.requiredPlan='professional';
    cards[2].dataset.planState=available(plan,'professional')?'preview':'locked';
    if(!available(plan,'professional'))cards[2].querySelectorAll('a[href="/watchlist"]').forEach(link=>{link.href='/pricing';link.textContent='View Professional';});
  }
}

function render(state){
  const host=document.getElementById('workspaceMissionControl');if(!host||document.getElementById('workspacePlanStrip'))return;
  const plan=state.active?state.plan:'none';
  const section=document.createElement('section');section.className='workspace-plan-strip';section.id='workspacePlanStrip';
  const copy=document.createElement('div');
  const eyebrow=document.createElement('span');eyebrow.className='eyebrow';eyebrow.textContent='Your workspace';
  const h3=document.createElement('h3');h3.textContent=state.signedOut?'Sign in to load your plan':state.unavailable?'Plan service unavailable':`${planLabel(plan)} workspace`;
  const p=document.createElement('p');
  if(state.active&&Number.isFinite(Number(state.remaining))&&Number.isFinite(Number(state.total)))p.textContent=`${state.remaining} of ${state.total} premium outputs remain. Plans change capacity and eligible surfaces, never the evidence itself.`;
  else p.textContent='Plans change capacity and eligible operational surfaces. They never rewrite evidence, grade, policy or confidence.';
  copy.append(eyebrow,h3,p);
  const badge=document.createElement('span');badge.className='workspace-plan-badge';badge.textContent=state.signedOut?'SIGNED OUT':state.unavailable?'UNAVAILABLE':plan==='none'?'NO ACTIVE PLAN':plan;
  section.append(copy,badge);
  const grid=document.createElement('div');grid.className='workspace-capability-grid';
  grid.append(
    capability('Core investigations','Starter and above: canonical ARVIS investigation path plus account-scoped investigation history.',available(plan,'starter')?'available':'locked'),
    capability('Advanced intelligence','Professional and above: advanced radar/watchlist eligibility. These surfaces remain preview until production validation completes.',available(plan,'professional')?'preview':'locked'),
    capability('Developer operations','Enterprise: API credential and integration eligibility. Registered developer routes remain readiness-gated.',available(plan,'enterprise')?'preview':'locked')
  );
  const wrap=document.createElement('div');wrap.append(section,grid);host.insertAdjacentElement('beforebegin',wrap);
  annotateWorkspace(plan);
}

ready(async()=>render(await loadAccess()));
})();