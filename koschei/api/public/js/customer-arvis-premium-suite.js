(()=>{
'use strict';
if(window.__customerARVISPremiumInstalled)return;
window.__customerARVISPremiumInstalled=true;

let latestPayload=null,mountTimer=0,videoURL='';
const originalFetch=window.fetch.bind(window);
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const clean=value=>String(value??'').trim();
const esc=value=>String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const rows=value=>Array.isArray(value)?value:[];
const compact=value=>{const text=clean(value);return text.length>34?`${text.slice(0,14)}…${text.slice(-12)}`:text;};

function requestURL(input){
  if(typeof input==='string')return input;
  if(input&&typeof input.url==='string')return input.url;
  return '';
}

function isCustomerScanRequest(url){
  const value=String(url||'');
  return value.includes('/api/token/scan')||value.includes('/api/arvis/preflight')||value.includes('/api/public/transaction-simulate');
}

window.fetch=async(...args)=>{
  const url=requestURL(args[0]);
  const response=await originalFetch(...args);
  try{
    const clone=response.clone(),type=clone.headers.get('content-type')||'';
    if(type.includes('json')){
      const data=await clone.json();
      if(hasInvestigation(data)){
        latestPayload=data;
        queueMount();
      }else if(isCustomerScanRequest(url)){
        latestPayload=null;
        clearTimeout(mountTimer);
      }
    }
  }catch{}
  return response;
};

function hasInvestigation(data){
  return Boolean(data&&typeof data==='object'&&(data.investigation_report||data.final_verdict||data.holder_intelligence||data.launch_forensics));
}

function canonicalReport(payload){
  const envelope=obj(payload),report=obj(envelope.investigation_report||envelope.report||envelope);
  return {envelope,report,final:obj(report.final_verdict||envelope.final_verdict)};
}

function payloadKey(payload){
  const {envelope,report,final}=canonicalReport(payload);
  return [
    report.target||envelope.target||envelope.mint||'',
    final.signature||report.signature||envelope.signature||'',
    final.generated_at||report.generated_at||envelope.generated_at||'',
    final.ruleset_version||report.ruleset_version||envelope.ruleset_version||'',
    final.grade||envelope.grade||''
  ].map(clean).join('|');
}

function resultRoot(){
  return document.getElementById('reportBody')||document.querySelector('[data-customer-arvis-result],#scanResult,#result');
}

function queueMount(){
  clearTimeout(mountTimer);
  mountTimer=setTimeout(mount,60);
}

function attackPathEvidence(ref){
  const evidence=obj(ref),groups=[];
  const push=(label,values)=>{const items=rows(values).map(compact).filter(Boolean);if(items.length)groups.push(`<div class="mini"><span>${esc(label)}</span><b>${esc(items.join(' · '))}</b></div>`);};
  push('Wallet',evidence.wallets);
  push('Account',evidence.accounts);
  push('Signature',evidence.signatures);
  push('Slot',evidence.slots);
  push('Evidence key',evidence.evidence_keys);
  return groups.join('');
}

function mountAttackPath(reportRoot,payload,anchor){
  reportRoot.querySelector('[data-arvis-attack-path]')?.remove();
  const {report}=canonicalReport(payload),attack=obj(report.attack_path),paths=rows(attack.paths),refs=obj(attack.evidence_references);
  if(!paths.length)return null;
  const section=document.createElement('section');
  section.className='panel full';
  section.dataset.arvisAttackPath='evidence-backed';
  section.innerHTML=`<span class="eyebrow">ATTACK PATH → CONCRETE EVIDENCE</span><h3>Olası saldırı yolları ve zincir üstü dayanakları</h3><p class="fine">Bu bölüm yeni risk üretmez; backend tarafından üretilmiş attack-path durumunu ve mevcut somut kanıt referanslarını gösterir. Kapasite, niyet kanıtı değildir.</p><div class="insights">${paths.map(path=>{
    const ref=obj(refs[clean(path.id)]),required=rows(path.required_evidence),limitations=rows(path.limitations),evidence=attackPathEvidence(ref);
    return `<div class="insight"><div class="actions"><span class="pill violet">${esc(clean(path.status)||'unknown')}</span><span class="pill">${esc(clean(path.evidence_status)||'unverified')}</span></div><b>${esc(path.label||path.id||'attack path')}</b><p>${esc(path.summary||'')}</p>${evidence||'<div class="empty">Bu yol için concrete evidence reference henüz yok; eksik kanıt güvenli sinyal sayılmaz.</div>'}${required.length?`<details><summary>Gerekli ek kanıt</summary><ul>${required.map(item=>`<li>${esc(item)}</li>`).join('')}</ul></details>`:''}${limitations.length?`<details><summary>Sınırlar</summary><ul>${limitations.map(item=>`<li>${esc(item)}</li>`).join('')}</ul></details>`:''}</div>`;
  }).join('')}</div>`;
  if(anchor&&anchor.parentNode===reportRoot)anchor.insertAdjacentElement('afterend',section);
  else reportRoot.prepend(section);
  return section;
}

function publishMounted(card,report,key){
  window.dispatchEvent(new CustomEvent('koschei:customer-premium-mounted',{detail:{card,root:report,payload:latestPayload,payloadKey:key}}));
}

function mount(){
  if(!latestPayload)return null;
  const report=resultRoot();
  if(!report)return null;
  const key=payloadKey(latestPayload);
  const existing=[...report.children].find(node=>node.matches?.('[data-arvis-premium-card]'));
  if(existing&&existing.dataset.customerPayloadKey===key){
    mountAttackPath(report,latestPayload,existing);
    return existing;
  }
  if(!window.KoscheiARVISPremium){
    mountAttackPath(report,latestPayload,null);
    return null;
  }
  const card=window.KoscheiARVISPremium.mountPremiumCard(report,latestPayload);
  if(!card)return null;
  card.dataset.customerPayloadKey=key;
  mountAttackPath(report,latestPayload,card);
  publishMounted(card,report,key);
  return card;
}

function modal(payload,platform='instagram'){
  latestPayload=payload||latestPayload;
  if(!latestPayload)return;
  document.getElementById('customerARVISStudio')?.remove();
  const api=window.KoscheiARVISPremium,overlay=document.createElement('div');
  overlay.id='customerARVISStudio';
  overlay.style.cssText='position:fixed;inset:0;z-index:99999;background:rgba(0,3,7,.88);backdrop-filter:blur(14px);padding:18px;overflow:auto';
  overlay.innerHTML=`<section class="arvis-social-studio" style="width:min(1180px,100%);margin:20px auto"><div class="arvis-social-top"><div><span class="arvis-kicker">CUSTOMER RESULT EXPORT</span><h2>Share the complete ARVIS evidence result</h2><p>The image, caption and video use the same canonical scan payload as the result card.</p></div><button class="arvis-action" id="customerStudioClose" type="button">Close</button></div><div class="arvis-social-tabs"><button class="arvis-social-tab ${platform==='x'?'active':''}" data-customer-format="x">X</button><button class="arvis-social-tab ${platform==='instagram'?'active':''}" data-customer-format="instagram">Instagram</button><button class="arvis-social-tab ${platform==='story'?'active':''}" data-customer-format="story">Story</button><button class="arvis-social-tab ${platform==='tiktok'?'active':''}" data-customer-format="tiktok">TikTok</button></div><div class="arvis-social-grid"><div class="arvis-preview-shell" id="customerStudioPreview"></div><div class="arvis-social-copy"><textarea class="arvis-caption" id="customerStudioCaption" readonly></textarea><div class="arvis-action-row"><button class="arvis-action primary" id="customerStudioImage">Download image</button><button class="arvis-action" id="customerStudioCopy">Copy caption</button><button class="arvis-action tiktok" id="customerStudioVideo" ${platform==='tiktok'?'':'hidden'}>Render vertical video</button></div><div class="arvis-progress"><span id="customerStudioProgress"></span></div><div id="customerStudioVideoResult"></div></div></div></section>`;
  document.body.appendChild(overlay);
  let current=platform;
  const draw=()=>{
    const preview=document.getElementById('customerStudioPreview');
    preview.replaceChildren(api.drawCardCanvas(latestPayload,current,current==='tiktok'?4:1,1));
    document.getElementById('customerStudioCaption').value=api.caption(latestPayload,current);
    document.getElementById('customerStudioVideo').hidden=current!=='tiktok';
    overlay.querySelectorAll('[data-customer-format]').forEach(button=>button.classList.toggle('active',button.dataset.customerFormat===current));
  };
  overlay.querySelectorAll('[data-customer-format]').forEach(button=>button.onclick=()=>{current=button.dataset.customerFormat;draw();});
  document.getElementById('customerStudioClose').onclick=()=>{if(videoURL)URL.revokeObjectURL(videoURL);overlay.remove();};
  document.getElementById('customerStudioCopy').onclick=()=>navigator.clipboard.writeText(api.caption(latestPayload,current));
  document.getElementById('customerStudioImage').onclick=async()=>api.downloadBlob(await api.canvasBlob(latestPayload,current),`koschei-arvis-${current}.png`);
  document.getElementById('customerStudioVideo').onclick=async()=>{
    const button=document.getElementById('customerStudioVideo'),bar=document.getElementById('customerStudioProgress'),result=document.getElementById('customerStudioVideoResult');
    button.disabled=true;button.textContent='Rendering…';
    try{
      const blob=await api.recordVerticalVideo(latestPayload,{duration:12000,onProgress:value=>bar.style.width=`${Math.round(value*100)}%`});
      if(videoURL)URL.revokeObjectURL(videoURL);
      videoURL=URL.createObjectURL(blob);
      const ext=blob.type.includes('mp4')?'mp4':'webm';
      result.innerHTML=`<video controls playsinline src="${videoURL}"></video><button class="arvis-action primary" id="customerStudioSaveVideo">Download ${ext.toUpperCase()}</button>`;
      document.getElementById('customerStudioSaveVideo').onclick=()=>api.downloadBlob(blob,`koschei-arvis-tiktok.${ext}`);
    }catch(error){
      result.innerHTML=`<div class="arvis-empty">${String(error.message||error)}</div>`;
    }finally{
      button.disabled=false;button.textContent='Render vertical video';
    }
  };
  draw();
}

window.KoscheiCustomerARVISPremium={mount,queueMount,payloadKey,get latestPayload(){return latestPayload;}};
window.addEventListener('koschei:open-social-studio',event=>modal(event.detail?.payload||latestPayload,event.detail?.platform||'instagram'));
const observer=new MutationObserver(()=>queueMount());
observer.observe(document.documentElement,{subtree:true,childList:true});
const timer=setInterval(()=>{if(window.KoscheiARVISPremium){clearInterval(timer);queueMount();}},50);
setTimeout(()=>clearInterval(timer),15000);
})();
