(()=>{
'use strict';

const $=id=>document.getElementById(id);

function ownerLoginURL(){
  const next='/owner-production';
  return '/login.html?next='+encodeURIComponent(next);
}

function prepareOwnerIdentityUI(){
  const secret=$('loginSecret');
  if(secret){
    const field=secret.closest('.field');
    if(field) field.style.display='none';
    secret.value='';
    secret.required=false;
  }
  const identity=$('loginWallet');
  const email=window.KoscheiAuth&&window.KoscheiAuth.getEmail?window.KoscheiAuth.getEmail():'';
  if(identity){
    identity.value=email||'';
    identity.readOnly=true;
    identity.required=false;
    identity.placeholder='Neon Auth owner identity';
  }
  const button=$('loginButton');
  if(button) button.textContent='Neon Auth ile kontrol merkezine gir';
}

async function verifyOwnerAccess(){
  if(!window.KoscheiAuth) throw new Error('Neon Auth istemcisi yüklenemedi.');
  const restored=await window.KoscheiAuth.init();
  if(!restored&&!window.KoscheiAuth.isLoggedIn()){
    window.location.href=ownerLoginURL();
    return false;
  }
  const response=await window.KoscheiAuth.apiCall('/api/owner/login',{
    method:'POST',
    credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body:'{}'
  });
  if(!response||!response.ok){
    if(response&&[401,403].includes(response.status)){
      window.location.href=ownerLoginURL();
      return false;
    }
    throw new Error('Bu Neon Auth hesabının owner erişimi yok.');
  }
  return true;
}

function bindOwnerLogout(){
  const signOut=async()=>{
    try{await fetch('/api/owner/logout',{method:'POST',credentials:'same-origin'});}catch{}
    if(window.KoscheiAuth&&window.KoscheiAuth.signOut){
      await window.KoscheiAuth.signOut();
      return;
    }
    window.location.href=ownerLoginURL();
  };
  for(const id of ['logoutButton','mobileLogoutButton']){
    const button=$(id);
    if(button) button.onclick=signOut;
  }
}

async function bindOwnerLogin(){
  prepareOwnerIdentityUI();
  bindOwnerLogout();
  const form=$('loginForm');
  if(!form) return;
  form.onsubmit=async event=>{
    event.preventDefault();
    const button=$('loginButton');
    const error=$('loginError');
    if(button){button.disabled=true;button.textContent='Owner kimliği doğrulanıyor…';}
    if(error){error.textContent='';error.classList.add('hidden');}
    try{
      if(await verifyOwnerAccess()) window.location.reload();
    }catch(err){
      if(error){error.textContent=err&&err.message?err.message:'Owner kimliği doğrulanamadı.';error.classList.remove('hidden');}
    }finally{
      if(button){button.disabled=false;button.textContent='Neon Auth ile kontrol merkezine gir';}
    }
  };
}

if(document.readyState==='loading') document.addEventListener('DOMContentLoaded',bindOwnerLogin,{once:true});
else bindOwnerLogin();
})();
