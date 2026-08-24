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

async function loadAccess(){
  try{
    await window.KoscheiAuth?.init?.();
    if(!window.KoscheiAuth?.isLoggedIn?.())return {plan:'none',active:false,signedOut:true};
    const response=await window.KoscheiAuth.apiCall('/api/auth/premium-access',{method:'GET'});
    const data=await response.json().catch(()=>({}));
    const access=data?.access||{};
    return {plan:normalizedPlan(access.plan),active:response.ok&&access.active===true,signedOut:false};
  }catch{return {plan:'none',active:false,signedOut:false,unavailable:true}}
}

function render(state){
  const host=document.getElementById('workspaceMissionControl');if(!host||document.getElementById('workspacePlanStrip'))return;
  const plan=state.active?state.plan:'none';
  const section=document.createElement('section');section.className='workspace-plan-strip';section.id='workspacePlanStrip';
  const copy=document.createElement('div');
  const eyebrow=document.createElement('span');eyebrow.className='eyebrow';eyebrow.textContent='Your workspace';
  const h3=document.createElement('h3');h3.textContent=state.signedOut?'Sign in to load your plan':state.unavailable?'Plan service unavailable':plan==='none'?'No active paid plan':`${plan[0].toUpperCase()}${plan.slice(1)} workspace`;
  const p=document.createElement('p');p.textContent='Plans change capacity and eligible operational surfaces. They never rewrite evidence, grade, policy or confidence.';
  copy.append(eyebrow,h3,p);
  const badge=document.createElement('span');badge.className='workspace-plan-badge';badge.textContent=state.signedOut?'SIGNED OUT':state.unavailable?'UNAVAILABLE':plan==='none'?'NO ACTIVE PLAN':plan;
  section.append(copy,badge);
  const grid=document.createElement('div');grid.className='workspace-capability-grid';
  grid.append(
    capability('Core investigations','Starter and above: canonical ARVIS investigation path plus account-scoped investigation history.',available(plan,'starter')?'available':'locked'),
    capability('Advanced intelligence','Professional and above: advanced radar/watchlist eligibility. Surfaces remain preview until their production validation is complete.',available(plan,'professional')?'preview':'locked'),
    capability('Developer operations','Enterprise: API credential and integration eligibility. Registered developer routes remain readiness-gated and do not imply every integration is production-complete.',available(plan,'enterprise')?'preview':'locked')
  );
  const wrap=document.createElement('div');wrap.append(section,grid);host.insertAdjacentElement('beforebegin',wrap);
}

ready(async()=>render(await loadAccess()));
})();