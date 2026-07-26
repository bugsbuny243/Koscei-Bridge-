(()=>{
'use strict';
if(window.__koscheiBoundedAPIFetchInstalled)return;
window.__koscheiBoundedAPIFetchInstalled=true;
const nativeFetch=window.fetch.bind(window);
const timeoutFor=path=>{
  if(path==='/health')return 10000;
  if(path.startsWith('/api/token/scan')||path.startsWith('/api/v1/radar/')||path.startsWith('/api/owner/')||path.startsWith('/api/jobs/'))return 45000;
  return 15000;
};
window.fetch=(input,init={})=>{
  let url;
  try{url=new URL(typeof input==='string'?input:input?.url||'',window.location.origin)}catch{return nativeFetch(input,init)}
  const bounded=url.origin===window.location.origin&&(url.pathname==='/health'||url.pathname.startsWith('/api/'));
  if(!bounded)return nativeFetch(input,init);
  const controller=new AbortController();
  const externalSignal=init.signal;
  let timedOut=false;
  const onExternalAbort=()=>controller.abort(externalSignal?.reason);
  if(externalSignal){if(externalSignal.aborted)onExternalAbort();else externalSignal.addEventListener('abort',onExternalAbort,{once:true})}
  const timeoutMs=timeoutFor(url.pathname);
  const timer=window.setTimeout(()=>{timedOut=true;controller.abort('koschei_api_timeout')},timeoutMs);
  return nativeFetch(input,{...init,signal:controller.signal}).catch(error=>{
    if(timedOut)throw new Error(`DEGRADED DEPENDENCY — Koschei API ${Math.round(timeoutMs/1000)} saniyede yanıt vermedi.`);
    throw error;
  }).finally(()=>{
    window.clearTimeout(timer);
    if(externalSignal)externalSignal.removeEventListener('abort',onExternalAbort);
  });
};
})();
