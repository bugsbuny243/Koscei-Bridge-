(()=>{
'use strict';

const $=id=>document.getElementById(id);

function setError(message=''){
  const error=$('loginError');
  if(!error)return;
  error.textContent=message;
  error.classList.toggle('hidden',!message);
}

function clearOwnerClientAuth(){
  try{
    localStorage.removeItem('koschei_jwt');
    localStorage.removeItem('koschei_token');
  }catch{}
}

async function verifyOwnerAccess(){
  if(!window.KoscheiAuth) throw new Error('Owner kimlik doğrulama istemcisi yüklenemedi.');
  const response=await window.KoscheiAuth.apiCall('/api/owner/login',{
    method:'POST',
    credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body:'{}'
  });
  if(!response||!response.ok){
    clearOwnerClientAuth();
    throw new Error(response&&response.status===403?'Bu hesap owner allowlist içinde değil.':'Owner kimliği doğrulanamadı.');
  }
  return true;
}

async function tryExistingOwnerSession(){
  if(!window.KoscheiAuth)return false;
  try{
    const restored=await window.KoscheiAuth.init();
    if(!restored&&!window.KoscheiAuth.isLoggedIn())return false;
    await verifyOwnerAccess();
    return true;
  }catch{
    clearOwnerClientAuth();
    return false;
  }
}

function bindOwnerLogout(){
  const signOut=async()=>{
    try{await fetch('/api/owner/logout',{method:'POST',credentials:'same-origin'});}catch{}
    clearOwnerClientAuth();
    window.location.reload();
  };
  for(const id of ['logoutButton','mobileLogoutButton']){
    const button=$(id);
    if(button) button.onclick=signOut;
  }
}

async function bindOwnerLogin(){
  bindOwnerLogout();
  const form=$('loginForm');
  if(!form)return;

  const emailField=$('loginWallet');
  if(emailField&&!emailField.value&&window.KoscheiAuth&&window.KoscheiAuth.getEmail){
    emailField.value=window.KoscheiAuth.getEmail()||'';
  }

  form.onsubmit=async event=>{
    event.preventDefault();
    const email=String($('loginWallet')?.value||'').trim();
    const password=String($('loginSecret')?.value||'');
    const button=$('loginButton');
    if(!email||!password){setError('Owner email ve parola gerekli.');return;}
    if(button){button.disabled=true;button.textContent='Owner kimliği doğrulanıyor…';}
    setError('');
    try{
      if(!window.KoscheiAuth)throw new Error('Owner kimlik doğrulama istemcisi yüklenemedi.');
      await window.KoscheiAuth.signIn(email,password);
      if(await verifyOwnerAccess())window.location.reload();
    }catch(err){
      clearOwnerClientAuth();
      if($('loginSecret'))$('loginSecret').value='';
      setError(err&&err.message?err.message:'Owner kimliği doğrulanamadı.');
    }finally{
      if(button){button.disabled=false;button.textContent='Kontrol merkezine gir';}
    }
  };

  await tryExistingOwnerSession();
}

if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bindOwnerLogin,{once:true});
else bindOwnerLogin();
})();
