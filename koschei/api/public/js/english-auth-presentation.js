(()=>{
'use strict';
if(window.__koscheiAuthEnglishOverlayInstalled)return;
window.__koscheiAuthEnglishOverlayInstalled=true;
document.documentElement.lang='en';

const TOKEN_KEY='koschei_jwt';
const LEGACY_TOKEN_KEY='koschei_token';
const nativeFetch=window.fetch.bind(window);

function isJWT(value){
  if(!value||typeof value!=='string')return false;
  const parts=value.split('.');
  return parts.length===3&&parts.every(Boolean);
}

function findJWT(value){
  if(!value||typeof value!=='object')return '';
  const candidates=[
    value.token,
    value.jwt,
    value.access_token,
    value.id_token,
    value.auth_token,
    value.data&&value.data.token,
    value.data&&value.data.jwt,
    value.data&&value.data.access_token,
    value.data&&value.data.id_token,
    value.session&&value.session.token,
    value.session&&value.session.jwt,
    value.session&&value.session.access_token,
    value.session&&value.session.id_token
  ];
  return candidates.find(isJWT)||'';
}

async function readJSON(response){
  const text=await response.text().catch(()=> '');
  if(!text)return {};
  try{return JSON.parse(text);}catch{return {message:text};}
}

function saveJWT(token){
  if(!isJWT(token))return;
  try{
    localStorage.setItem(TOKEN_KEY,token);
    localStorage.setItem(LEGACY_TOKEN_KEY,token);
  }catch{}
}

function clearJWT(){
  try{
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(LEGACY_TOKEN_KEY);
  }catch{}
}

function authError(data,fallback){
  const raw=String((data&&(data.message||data.error_description||data.error||data.detail))||'').trim();
  if(!raw)return fallback;
  const normalized=raw.toLowerCase();
  if(normalized.includes('invalid email or password')||normalized.includes('invalid credentials'))return 'Invalid email or password.';
  if(normalized.includes('auth_session_missing')||normalized.includes('session token'))return 'The authentication provider did not return a session. Please try again.';
  if(normalized.includes('temporarily unreachable')||normalized.includes('unavailable'))return 'Authentication is temporarily unavailable. Please try again.';
  return raw;
}

async function sameOriginEmailAuth(path,email,password,includeName){
  const payload={
    email:String(email||'').trim(),
    password:String(password||''),
    callbackURL:window.location.origin.replace(/\/+$/,'')+'/dashboard'
  };
  if(includeName){
    payload.name=(payload.email.split('@')[0]||'User').trim()||'User';
  }
  const response=await nativeFetch(path,{
    method:'POST',
    credentials:'same-origin',
    headers:{'Content-Type':'application/json'},
    body:JSON.stringify(payload)
  });
  const data=await readJSON(response);
  if(!response.ok)throw new Error(authError(data,includeName?'Account creation failed.':'Sign-in failed.'));
  const token=findJWT(data);
  if(!token)throw new Error('The authentication provider did not return a session. Please try again.');
  saveJWT(token);
  const meResponse=await nativeFetch('/api/me',{
    method:'GET',
    credentials:'same-origin',
    headers:{Authorization:'Bearer '+token}
  });
  const me=await readJSON(meResponse);
  if(!meResponse.ok){
    clearJWT();
    throw new Error(authError(me,'The authenticated session could not be verified.'));
  }
  return {...data,me,access_token:token,token_type:'Bearer'};
}

function installSameOriginAuthContract(){
  const auth=window.KoscheiAuth;
  if(!auth||window.__koscheiSameOriginEmailAuthInstalled)return false;
  window.__koscheiSameOriginEmailAuthInstalled=true;
  auth.signIn=(email,password)=>sameOriginEmailAuth('/api/auth/login',email,password,false);
  auth.signUp=(email,password)=>sameOriginEmailAuth('/api/auth/register',email,password,true);
  return true;
}

// The frozen auth helper may start a provider-session restore while /api/config
// is resolving. Block only those cross-origin restore probes; email/password
// authentication is always handled through the same-origin backend contract.
window.fetch=async function(input,init){
  try{
    const raw=typeof input==='string'?input:(input&&input.url)||'';
    const target=new URL(raw,window.location.origin);
    const crossOrigin=target.origin!==window.location.origin;
    const providerHost=/neonauth\.|\.neon\.tech$/i.test(target.hostname);
    const providerSessionPath=/(?:\/token|\/get-session)$/i.test(target.pathname);
    if(crossOrigin&&providerHost&&providerSessionPath){
      return new Response('{}',{status:404,headers:{'Content-Type':'application/json'}});
    }
  }catch{}
  return nativeFetch(input,init);
};

installSameOriginAuthContract();
queueMicrotask(installSameOriginAuthContract);
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',installSameOriginAuthContract,{once:true});

const exact=new Map(Object.entries({
  'Giriş Yap':'Sign In',
  'Hesap Oluştur':'Create Account',
  'E-posta':'Email',
  'Şifre':'Password',
  'Şifreyi onayla':'Confirm password',
  'Hesabınız yok mu?':'No account yet?',
  'Hesap oluştur':'Create an account',
  'Zaten hesabınız var mı?':'Already have an account?',
  'Hesap oturumunu aç. Derin ARVIS araçları için girişten sonra Phantom cüzdanını doğrula ve KOSCH holder durumunu kontrol et.':'Open your account session. After signing in, verify your Phantom wallet and KOSCH holder status to unlock deep ARVIS tools.',
  'Hesap ücretsiz oluşturulur. Public Safe Check açıktır; derin ürün erişimi doğrulanmış KOSCH bakiyesiyle açılır.':'Account creation is free. Public Safe Check remains open; deep product access unlocks through a verified KOSCH balance.',
  '✓ Paket veya kart bilgisi gerekmez':'✓ No package or payment card is required',
  '✓ Phantom yalnız mesaj imzalar':'✓ Phantom signs a message only',
  "✓ KOSCH bakiyesi ürün tier'ını otomatik açar":'✓ Verified KOSCH balance unlocks the product tier automatically',
  'Giriş başarılı.':'Sign-in successful.',
  'Giriş yapılamadı.':'Sign-in failed.',
  'Geçerli e-posta girin.':'Enter a valid email address.',
  'Şifre en az 8 karakter olmalı.':'Password must contain at least 8 characters.',
  'Şifreler eşleşmiyor.':'Passwords do not match.',
  'Hesap oluşturuldu.':'Account created.',
  'Hesap oluşturulamadı.':'Account creation failed.'
}));

function translateText(value){
  const source=String(value||'');
  const trimmed=source.trim();
  if(!trimmed)return source;
  let translated=exact.get(trimmed);
  if(!translated){
    translated=trimmed
      .replace(/^Giriş Yap\s*[—-]\s*/,'Sign In — ')
      .replace(/^Hesap Oluştur\s*[—-]\s*/,'Create Account — ')
      .replace(/Koschei ARVIS hesabınıza Neon Auth ile giriş yapın; derin araçlar doğrulanmış KOSCH holder access gerektirir\./g,'Sign in to Koschei ARVIS with Neon Auth. Deep investigation tools require verified KOSCH holder access.')
      .replace(/Koschei ARVIS hesabınızı Neon Auth ile oluşturun; derin araçlar doğrulanmış KOSCH holder access ile açılır\./g,'Create a Koschei ARVIS account with Neon Auth. Deep tools unlock through verified KOSCH holder access.');
  }
  if(translated===trimmed&&translated===source)return source;
  const leading=source.match(/^\s*/)?.[0]||'';
  const trailing=source.match(/\s*$/)?.[0]||'';
  return leading+translated+trailing;
}

function visit(node){
  if(node.nodeType===Node.TEXT_NODE){
    const parent=node.parentElement;
    if(!parent||['SCRIPT','STYLE','CODE','PRE'].includes(parent.tagName))return;
    const translated=translateText(node.nodeValue);
    if(translated!==node.nodeValue)node.nodeValue=translated;
    return;
  }
  if(node.nodeType!==Node.ELEMENT_NODE)return;
  const element=node;
  if(element.hasAttribute('placeholder'))element.setAttribute('placeholder',translateText(element.getAttribute('placeholder')));
  if(element.tagName==='TITLE')element.textContent=translateText(element.textContent);
  for(const child of element.childNodes)visit(child);
}

function run(){
  installSameOriginAuthContract();
  document.title=translateText(document.title);
  document.querySelectorAll('meta[name="description"]').forEach(meta=>meta.setAttribute('content',translateText(meta.getAttribute('content'))));
  if(document.body)visit(document.body);
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',run);else run();
new MutationObserver(records=>{for(const record of records){if(record.type==='characterData')visit(record.target);for(const node of record.addedNodes)visit(node);}}).observe(document.documentElement,{subtree:true,childList:true,characterData:true});
})();
