(()=>{
'use strict';
if(window.__koscheiAuthEnglishOverlayInstalled)return;
window.__koscheiAuthEnglishOverlayInstalled=true;
document.documentElement.lang='en';

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
  const text=String(value||'');
  const trimmed=text.trim();
  if(!trimmed)return text;
  let translated=exact.get(trimmed);
  if(!translated){
    translated=trimmed
      .replace(/^Giriş Yap\s*[—-]\s*/,'Sign In — ')
      .replace(/^Hesap Oluştur\s*[—-]\s*/,'Create Account — ')
      .replace(/Koschei ARVIS hesabınıza Neon Auth ile giriş yapın; derin araçlar doğrulanmış KOSCH holder access gerektirir\./g,'Sign in to Koschei ARVIS with Neon Auth. Deep investigation tools require verified KOSCH holder access.')
      .replace(/Koschei ARVIS hesabınızı Neon Auth ile oluşturun; derin araçlar doğrulanmış KOSCH holder access ile açılır\./g,'Create a Koschei ARVIS account with Neon Auth. Deep tools unlock through verified KOSCH holder access.');
  }
  if(translated===trimmed&&translated===text)return text;
  const leading=text.match(/^\s*/)?.[0]||'';
  const trailing=text.match(/\s*$/)?.[0]||'';
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
  document.title=translateText(document.title);
  document.querySelectorAll('meta[name="description"]').forEach(meta=>meta.setAttribute('content',translateText(meta.getAttribute('content'))));
  if(document.body)visit(document.body);
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',run);else run();
new MutationObserver(records=>{for(const record of records){if(record.type==='characterData')visit(record.target);for(const node of record.addedNodes)visit(node);}}).observe(document.documentElement,{subtree:true,childList:true,characterData:true});
})();
