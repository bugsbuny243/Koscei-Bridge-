(()=>{
'use strict';
if(window.__koscheiPricingPolicyV2)return;
window.__koscheiPricingPolicyV2=true;

const $=id=>document.getElementById(id);
const text=value=>String(value??'').trim();
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const tierOrder=['basic','pro','enterprise'];

function el(tag,className,value){const node=document.createElement(tag);if(className)node.className=className;if(value!==undefined)node.textContent=String(value);return node;}
function setStatus(message,tone='warn'){const node=$('policyStatus');if(!node)return;node.textContent=message;node.className=`pricing-policy-status ${tone}`;}
function thresholdText(value){const clean=text(value);return clean?`${clean} KOSCH`:'UNAVAILABLE';}
function renderThresholds(access){
  const thresholds=obj(access?.thresholds),host=$('policyThresholds');if(!host)return;
  host.replaceChildren();
  for(const tier of tierOrder){
    const card=el('article','pricing-policy-tier');
    card.dataset.tier=tier;
    card.append(el('span','',`${tier.toUpperCase()} THRESHOLD`),el('strong','',thresholdText(thresholds[tier])),el('small','',thresholds[tier]!==undefined?'Returned by the current token-access policy.':'Current policy did not return this threshold. The UI does not guess a legacy value.'));
    host.append(card);
  }
}
function renderSignedOut(){renderThresholds({});setStatus('Sign in to view the current live KOSCH thresholds. This public page does not hardcode or guess token-tier policy.','neutral');const summary=$('accountPolicy');if(summary)summary.textContent='Signed out · live holder thresholds unavailable on this public session.';}
function renderUnavailable(message){renderThresholds({});setStatus(message||'Token-access policy is unavailable. No legacy threshold is shown.','bad');const summary=$('accountPolicy');if(summary)summary.textContent='Policy unavailable · no tier state inferred.';}
function renderAccess(access){
  renderThresholds(access);
  const configured=access.configured===true,gate=access.gate_enabled===true,verified=access.wallet_verified===true,tier=(text(access.tier)||'none').toUpperCase();
  setStatus(configured&&gate?'Live token-access policy loaded. Thresholds below are authoritative for this session.':'Token-access policy loaded, but the holder gate is not fully active/configured. Do not infer premium access from balance alone.',configured&&gate?'good':'warn');
  const summary=$('accountPolicy');if(summary)summary.textContent=`Current account · tier ${tier} · wallet ${verified?'verified':'not verified'} · gate ${gate?'active':'disabled'}`;
}
async function bootstrap(){
  if(!window.KoscheiAuth){renderSignedOut();return;}
  try{await KoscheiAuth.init();}catch{renderSignedOut();return;}
  if(!KoscheiAuth.isLoggedIn?.()){renderSignedOut();return;}
  try{
    const response=await KoscheiAuth.apiCall('/api/auth/token-access',{method:'GET'});if(!response){renderUnavailable('Token-access policy could not be reached. No threshold was inferred.');return;}
    const data=await response.json().catch(()=>({}));if(!response.ok||data?.ok!==true){renderUnavailable(data?.message||data?.error||`Token-access policy unavailable (${response.status}).`);return;}
    renderAccess(obj(data.access));
  }catch(error){renderUnavailable(error?.message||'Token-access policy could not be resolved.');}
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bootstrap);else bootstrap();
})();
