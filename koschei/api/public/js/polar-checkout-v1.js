(()=>{
'use strict';
if(window.__koscheiPolarCheckoutV1)return;
window.__koscheiPolarCheckoutV1=true;

const text=value=>String(value??'').trim();
const buttons=()=>Array.from(document.querySelectorAll('[data-polar-plan]'));
const message=()=>document.getElementById('polarBillingMessage');

function showMessage(value,tone='warn'){
  const node=message();
  if(!node)return;
  node.hidden=false;
  node.textContent=value;
  node.dataset.tone=tone;
}

async function readJSON(response){
  const raw=await response.text().catch(()=> '');
  if(!raw)return {};
  try{return JSON.parse(raw);}catch{return {error:'invalid_json_response'};}
}

function login(){
  const target=window.KoscheiAuth?.loginURL?.('/login.html')||'/login.html?next=%2Fpricing';
  window.location.href=target;
}

async function openCheckout(button){
  if(!button||button.disabled)return;
  const plan=text(button.dataset.polarPlan).toLowerCase();
  if(plan!=='professional')return;
  const original=button.textContent;
  button.disabled=true;
  button.setAttribute('aria-busy','true');
  button.textContent='Opening secure checkout…';
  try{
    if(!window.KoscheiAuth)throw new Error('Koschei account service is unavailable.');
    try{await KoscheiAuth.init();}catch{}
    if(!KoscheiAuth.isLoggedIn()){login();return;}
    const response=await KoscheiAuth.apiCall('/api/polar/checkout',{
      method:'POST',
      headers:{'Content-Type':'application/json'},
      body:JSON.stringify({plan:'professional'}),
      credentials:'same-origin',
    });
    if(!response)throw new Error('Checkout service is unavailable.');
    const data=await readJSON(response);
    if(response.status===401){login();return;}
    if(!response.ok){
      if(data?.error==='polar_checkout_not_configured')throw new Error('Secure Professional checkout is not configured yet.');
      if(data?.error==='customer_binding_mismatch'||data?.error==='verified_identity_required')throw new Error('Your verified account identity is required before checkout.');
      throw new Error('Secure checkout could not be opened.');
    }
    const checkoutURL=text(data?.checkout_url);
    let parsed;
    try{parsed=new URL(checkoutURL);}catch{throw new Error('Checkout service returned an invalid URL.');}
    if(parsed.protocol!=='https:')throw new Error('Checkout service returned an insecure URL.');
    window.location.assign(parsed.toString());
  }catch(error){
    showMessage(error?.message||'Secure checkout could not be opened.','bad');
  }finally{
    button.disabled=false;
    button.removeAttribute('aria-busy');
    button.textContent=original;
  }
}

function bootstrap(){
  buttons().forEach(button=>button.addEventListener('click',()=>openCheckout(button)));
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bootstrap);else bootstrap();
})();
