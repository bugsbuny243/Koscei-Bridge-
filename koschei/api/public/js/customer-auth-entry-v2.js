(()=>{
'use strict';
if(window.__koscheiCustomerAuthEntryV2)return;
window.__koscheiCustomerAuthEntryV2=true;

const $=id=>document.getElementById(id);
const text=value=>String(value??'').trim();
const mode=()=>document.body?.dataset?.authMode==='register'?'register':'login';

function show(message,tone='bad'){
  const node=$('authMessage');if(!node)return;
  node.textContent=message;node.className=`auth-message show ${tone}`;
}
function clear(){const node=$('authMessage');if(node){node.textContent='';node.className='auth-message';}}
function nextPath(){return window.KoscheiAuth?.nextPath?.()||'/dashboard';}
function setNext(){const next=nextPath();const node=$('authNext');if(node)node.textContent=next;return next;}
function loginURL(next,email=''){
  const params=new URLSearchParams();params.set('next',next);params.set('registered','1');if(email)params.set('email',email);return`/login?${params.toString()}`;
}

async function submit(event){
  event.preventDefault();clear();
  const form=$('authForm'),button=$('authSubmit');if(!form||!button)return;
  const email=text($('authEmail')?.value),password=String($('authPassword')?.value||''),next=nextPath();
  if(!email||!password){show('Email and password are required.');return;}
  if(mode()==='register'){
    const confirm=String($('authConfirm')?.value||'');
    if(password!==confirm){show('Password confirmation does not match.');return;}
  }
  const previous=button.textContent;button.disabled=true;button.textContent=mode()==='register'?'Creating secure account…':'Signing in…';
  try{
    if(mode()==='register'){
      await KoscheiAuth.signUp(email,password);
      if(KoscheiAuth.isLoggedIn?.()){
        location.replace(next);return;
      }
      location.replace(loginURL(next,email));return;
    }
    await KoscheiAuth.signIn(email,password);
    location.replace(next);
  }catch(error){
    show(error?.message||'Authentication could not be completed.');
  }finally{
    button.disabled=false;button.textContent=previous;
  }
}

async function bootstrap(){
  if(!window.KoscheiAuth){show('Authentication client is unavailable. No session state was inferred.');return;}
  try{await KoscheiAuth.init();}catch(error){show(error?.message||'Authentication initialization failed.');return;}
  const next=setNext();
  if(KoscheiAuth.isLoggedIn?.()){location.replace(next);return;}
  const params=new URLSearchParams(location.search);
  const email=text(params.get('email'));
  if(email&&$('authEmail'))$('authEmail').value=email;
  if(mode()==='login'&&params.get('registered')==='1')show('Account created. Sign in to continue to the requested Koschei surface.','good');
  $('authForm')?.addEventListener('submit',submit);
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bootstrap);else bootstrap();
})();
