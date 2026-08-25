(()=>{
'use strict';

const PLATFORMS={
  x:{label:'X',kind:'video',hint:'Short hook + evidence + compact hashtags',format:'x'},
  instagram:{label:'Instagram Reels',kind:'vertical',hint:'9:16 Reel + caption + hashtags',format:'story'},
  tiktok:{label:'TikTok',kind:'vertical',hint:'9:16 video + hook + voiceover',format:'tiktok'},
  youtube:{label:'YouTube Shorts',kind:'vertical',hint:'Short title + description + tags',format:'tiktok'}
};
const state={payload:null,platform:'x',videoURL:'',videoBlob:null,busy:false,aiBusy:false,aiPack:null,aiThread:sessionStorage.getItem('koschei.social.ai.thread')||''};
const $=id=>document.getElementById(id);
const esc=value=>String(value??'').replace(/[&<>"']/g,ch=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const arr=value=>Array.isArray(value)?value:[];
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const owner=()=>window.KoscheiOwner;

function ensurePage(){let page=$('page-social-studio');if(page)return page;page=document.createElement('section');page.className='page';page.id='page-social-studio';page.innerHTML='<div id="socialStudioContent"></div>';document.querySelector('.owner-app>.main')?.appendChild(page);return page;}
function navButton(mobile=false){const button=document.createElement('button');button.type='button';button.dataset.socialStudioNav='1';button.className=mobile?'':'nav-item';button.innerHTML=mobile?'<span>▶</span>Sosyal':`<span class="nav-icon">▶</span><span>Sosyal Medya</span>`;button.onclick=()=>activate();return button;}
function ensureNav(){const desktop=$('desktopNav'),mobile=$('mobileNav');if(desktop&&!desktop.querySelector('[data-social-studio-nav]'))desktop.appendChild(navButton());if(mobile&&!mobile.querySelector('[data-social-studio-nav]'))mobile.appendChild(navButton(true));reorder(desktop);reorder(mobile);}
function reorder(root){if(!root)return;const customer=root.querySelector('[data-nav="customers"]'),social=root.querySelector('[data-social-studio-nav]');if(customer&&root.firstElementChild!==customer)root.prepend(customer);if(customer&&social&&customer.nextElementSibling!==social)customer.after(social);}
function activate(payload=state.payload,platform=state.platform){state.payload=payload||window.OwnerRadarKit?.lastScan||state.payload;state.platform=PLATFORMS[platform]?platform:'x';const page=ensurePage();document.querySelectorAll('.page').forEach(section=>section.classList.toggle('active',section===page));document.querySelectorAll('[data-nav],[data-publishing-nav],[data-social-studio-nav]').forEach(button=>button.classList.toggle('active',button.dataset.socialStudioNav==='1'));if($('pageTitle'))$('pageTitle').textContent='Sosyal Medya Yayın Merkezi';if($('pageEyebrow'))$('pageEyebrow').textContent='2 · ARVIS sonucu → Together AI metni → video → paylaşım';render();}

function defaultPack(payload){
  const api=window.KoscheiARVISPremium;
  const platform=state.platform;
  const caption=api?.caption?.(payload,platform==='youtube'?'tiktok':platform)||'';
  const voiceover=api?.voiceoverScript?.(payload)||'';
  const symbol=String(payload?.symbol||payload?.token_symbol||obj(payload?.signals).symbol||'ARVIS').replace(/^\$/,'').toUpperCase();
  const risk=String(payload?.risk_level||payload?.riskLevel||obj(payload?.signals).risk_level||'evidence review').toUpperCase();
  return{
    title:`KOSCHEI ARVIS · ${symbol} · ${risk}`,
    caption,
    description:caption,
    hashtags:['#Koschei','#ARVIS','#Web3Security','#Solana'],
    mentions:[],
    voiceover,
    hook:`ARVIS scan: ${symbol}`,
    cta:'Verify the evidence. Do your own research.'
  };
}
function currentPack(){return state.aiPack||defaultPack(state.payload||{});}
function formatTags(values,prefix=''){return arr(values).map(value=>String(value||'').trim()).filter(Boolean).map(value=>prefix&& !value.startsWith(prefix)?prefix+value:value).join(' ');}
function render(){
  ensureNav();
  const root=$('socialStudioContent');if(!root)return;
  const api=window.KoscheiARVISPremium;
  if(!api){root.innerHTML='<div class="arvis-empty">ARVIS media renderer yükleniyor.</div>';return;}
  const payload=state.payload||window.OwnerRadarKit?.lastScan;
  if(payload&&!state.payload)state.payload=payload;
  const pack=payload?currentPack():defaultPack({});
  const spec=PLATFORMS[state.platform];
  root.innerHTML=`<section class="arvis-social-studio">
    <div class="arvis-social-top"><div><span class="arvis-kicker">2 · SOSYAL MEDYA</span><h2>Bir taramadan dört platform için yayın paketi.</h2><p>ARVIS bulgusunu değiştirmeden X, Instagram, TikTok ve YouTube için video, açıklama, hashtag, mention/tag ve voiceover hazırlar. Metin tarafında Together AI kullanılır; kanıt verisi ARVIS'ten gelir.</p></div><div class="arvis-chip-row"><span class="arvis-chip good">OWNER ONLY</span><span class="arvis-chip info">TOGETHER AI</span></div></div>
    <div class="arvis-social-controls"><input id="socialStudioTarget" class="mono" placeholder="Solana mint veya adres" value="${esc(payload?.target||payload?.mint||'')}"><button class="arvis-action primary" id="socialStudioScan" type="button">ARVIS Tam Tara</button></div>
    <div class="arvis-social-tabs">${Object.entries(PLATFORMS).map(([id,item])=>`<button class="arvis-social-tab ${state.platform===id?'active':''}" data-social-platform="${id}" type="button">${esc(item.label)}</button>`).join('')}</div>
    <div class="social-platform-meta"><span class="arvis-chip info">${esc(spec.hint)}</span><span class="arvis-chip">Evidence synchronized</span><span class="arvis-chip">No invented facts</span></div>
    <div class="social-pack-grid">
      <div class="social-pack-panel">
        <div class="arvis-preview-shell" id="socialStudioPreview">${payload?'':'<div class="arvis-empty">ARVIS sonucu seç veya yeni tarama çalıştır.</div>'}</div>
        <div class="social-video-box" id="socialStudioVideoResult">${state.videoURL?`<video controls playsinline src="${state.videoURL}"></video>`:'<div class="social-video-empty">Video henüz üretilmedi. ARVIS sonucunu seçip “Video oluştur”a bas.</div>'}</div>
        <div class="social-progress-track"><span id="socialStudioProgress"></span></div>
        <div class="social-action-stack">
          <button class="arvis-action tiktok" id="socialStudioVideo" type="button" ${payload?'':'disabled'}>${state.busy?'Video hazırlanıyor…':'Video oluştur'}</button>
          <button class="arvis-action" id="socialStudioSaveVideo" type="button" ${state.videoBlob?'':'disabled'}>Videoyu indir</button>
          <button class="arvis-action" id="socialStudioShare" type="button" ${state.videoBlob?'':'disabled'}>Telefondan paylaş</button>
          <button class="arvis-action" id="socialStudioImage" type="button" ${payload?'':'disabled'}>Kapak görselini indir</button>
        </div>
        <p class="social-evidence-note">Video renderer gerçek ARVIS payload'ını kullanır. Together AI yalnızca anlatım, açıklama ve sosyal metin üretir; risk skoru, adres veya işlem kanıtı uydurmasına izin verilmez.</p>
      </div>
      <div class="social-pack-panel">
        <div class="social-ai-status"><div><b>Together AI Content Pack</b><div class="muted small">${state.aiPack?'AI metni hazır':'Deterministik metin hazır · AI ile iyileştirilebilir'}</div></div><button class="arvis-action primary" id="socialStudioAI" type="button" ${payload&&!state.aiBusy?'':'disabled'}>${state.aiBusy?'Hazırlanıyor…':'Together AI ile hazırla'}</button></div>
        <div class="social-field"><label>BAŞLIK / HOOK</label><input class="input" id="socialTitle" readonly value="${esc(pack.title||pack.hook||'')}"></div>
        <div class="social-field"><label>PAYLAŞIM METNİ</label><textarea class="arvis-caption" id="socialCaption" readonly>${esc(pack.caption||'')}</textarea></div>
        <div class="social-field"><label>AÇIKLAMA</label><textarea class="arvis-caption" id="socialDescription" readonly>${esc(pack.description||'')}</textarea></div>
        <div class="social-field"><label>HASHTAG</label><textarea class="arvis-caption" data-short id="socialHashtags" readonly>${esc(formatTags(pack.hashtags,'#'))}</textarea></div>
        <div class="social-field"><label>TAG / MENTION</label><textarea class="arvis-caption" data-short id="socialMentions" readonly>${esc(formatTags(pack.mentions,'@')||'—')}</textarea></div>
        <div class="social-field"><label>VOICEOVER</label><textarea class="arvis-caption" id="socialVoiceover" readonly>${esc(pack.voiceover||'')}</textarea></div>
        <div class="social-action-stack"><button class="arvis-action primary" id="socialCopyPack" type="button" ${payload?'':'disabled'}>Tüm paketi kopyala</button><button class="arvis-action" id="socialCopyCaption" type="button" ${payload?'':'disabled'}>Metni kopyala</button><button class="arvis-action" id="socialCopyDescription" type="button" ${payload?'':'disabled'}>Açıklamayı kopyala</button></div>
      </div>
    </div>
  </section>`;
  bind(payload);if(payload)drawPreview(payload);
}

function drawPreview(payload){const api=window.KoscheiARVISPremium,preview=$('socialStudioPreview');if(!api||!preview)return;const format=PLATFORMS[state.platform]?.format||'tiktok';preview.replaceChildren(api.drawCardCanvas(payload,format,state.platform==='x'?1:4,1));}
function bind(payload){
  document.querySelectorAll('[data-social-platform]').forEach(button=>button.onclick=()=>{state.platform=button.dataset.socialPlatform;state.aiPack=null;render();});
  $('socialStudioScan')?.addEventListener('click',async()=>{const target=$('socialStudioTarget').value.trim();if(!target)return;const button=$('socialStudioScan');button.disabled=true;button.textContent='Taranıyor…';try{const result=await owner().api('/api/owner/arvis/scan',{method:'POST',body:JSON.stringify({target,network:'solana-mainnet'})});state.payload=result;state.aiPack=null;clearVideo();render();}catch(error){button.textContent=error.message||'Tarama başarısız';button.disabled=false;}});
  $('socialStudioAI')?.addEventListener('click',()=>composeAI(payload));
  $('socialStudioVideo')?.addEventListener('click',()=>renderVideo(payload));
  $('socialStudioSaveVideo')?.addEventListener('click',()=>saveVideo(payload));
  $('socialStudioShare')?.addEventListener('click',()=>shareVideo(payload));
  $('socialStudioImage')?.addEventListener('click',()=>downloadImage(payload));
  $('socialCopyPack')?.addEventListener('click',()=>copyText(packText()));
  $('socialCopyCaption')?.addEventListener('click',()=>copyText(currentPack().caption||''));
  $('socialCopyDescription')?.addEventListener('click',()=>copyText(currentPack().description||''));
}
function compactScan(payload){
  const signals=obj(payload?.signals),market=obj(payload?.market),summary=obj(payload?.summary),verdict=obj(payload?.verdict);
  const evidence=arr(payload?.evidence).slice(0,6).map(value=>typeof value==='string'?value:JSON.stringify(value).slice(0,220));
  const pick={target:payload?.target||payload?.mint||'',symbol:payload?.symbol||payload?.token_symbol||signals.symbol||'',name:payload?.name||payload?.token_name||signals.name||'',network:payload?.network||'solana-mainnet',grade:payload?.grade||verdict.grade||signals.grade||'',risk_level:payload?.risk_level||payload?.riskLevel||verdict.risk_level||signals.risk_level||'',verdict:typeof payload?.verdict==='string'?payload.verdict:verdict.summary||verdict.label||'',report_status:payload?.report_status||'',signed:Boolean(payload?.signed||verdict.signed),rule_version:payload?.rule_version||payload?.ruleset_version||'',market_cap_usd:payload?.market_cap_usd||market.market_cap_usd||signals.market_cap_usd||0,liquidity_usd:payload?.liquidity_usd||market.liquidity_usd||signals.liquidity_usd||0,volume_24h_usd:payload?.volume_24h_usd||market.volume_24h_usd||signals.volume_24h_usd||0,holder_count:payload?.holder_count||summary.holder_count||signals.holder_count||0,top_holder_pct:payload?.top_holder_percentage||summary.top_holder_percentage||signals.top_holder_percentage||0,creator:payload?.creator||payload?.creator_wallet||signals.creator||'',evidence};
  return pick;
}
function aiPrompt(payload){
  const spec=PLATFORMS[state.platform];
  const scan=JSON.stringify(compactScan(payload));
  return `SOCIAL_STUDIO_REQUEST\nPlatform: ${spec.label}\nReturn ONLY one JSON object with exactly these keys: title, caption, description, hashtags, mentions, voiceover, hook, cta. hashtags and mentions must be arrays of strings. Write public-facing content in English. Use ONLY the supplied ARVIS scan facts. Never invent a wallet, transaction, price, score, crime, identity, partnership, endorsement or certainty. Separate observation from assessment. If evidence is incomplete, say so. Do not promise investment returns. Keep caption platform-native and concise. Voiceover should be 35-55 seconds. For YouTube include a searchable short title and fuller description. For X keep caption compact.\nARVIS_SCAN=${scan}`.slice(0,3900);
}
function parseJSONObject(text){let value=String(text||'').trim().replace(/^```json\s*/i,'').replace(/^```\s*/,'').replace(/```$/,'').trim();const start=value.indexOf('{'),end=value.lastIndexOf('}');if(start<0||end<start)throw new Error('AI JSON output bulunamadı.');return JSON.parse(value.slice(start,end+1));}
function normalizePack(value,payload){const fallback=defaultPack(payload);const data=obj(value);return{title:String(data.title||fallback.title).slice(0,160),caption:String(data.caption||fallback.caption).slice(0,2200),description:String(data.description||data.caption||fallback.description).slice(0,4000),hashtags:arr(data.hashtags).slice(0,14).map(v=>String(v).replace(/^#/,'')).filter(Boolean),mentions:arr(data.mentions).slice(0,10).map(v=>String(v).replace(/^@/,'')).filter(Boolean),voiceover:String(data.voiceover||fallback.voiceover).slice(0,1800),hook:String(data.hook||data.title||fallback.hook).slice(0,240),cta:String(data.cta||fallback.cta).slice(0,300)};}
async function composeAI(payload){if(!payload||state.aiBusy)return;state.aiBusy=true;render();try{const body={message:aiPrompt(payload)};if(state.aiThread)body.thread_id=state.aiThread;const response=await owner().api('/api/owner/chat',{method:'POST',body:JSON.stringify(body)});if(response.thread_id){state.aiThread=response.thread_id;sessionStorage.setItem('koschei.social.ai.thread',response.thread_id);}state.aiPack=normalizePack(parseJSONObject(response.assistant_message?.content||''),payload);render();}catch(error){state.aiBusy=false;render();alert(`Together AI metni üretilemedi: ${error.message||'Bilinmeyen hata'}`);return;}state.aiBusy=false;render();}
async function renderVideo(payload){if(!payload||state.busy)return;state.busy=true;render();try{const progress=$('socialStudioProgress');const blob=await window.KoscheiARVISPremium.recordVerticalVideo(payload,{duration:15000,onProgress:value=>{if(progress)progress.style.width=`${Math.round(value*100)}%`;}});clearVideo();state.videoBlob=blob;state.videoURL=URL.createObjectURL(blob);}catch(error){alert(error.message||'Video üretilemedi.');}finally{state.busy=false;render();}}
function clearVideo(){if(state.videoURL)URL.revokeObjectURL(state.videoURL);state.videoURL='';state.videoBlob=null;}
function fileName(payload,ext){const target=String(payload?.target||payload?.mint||'result').slice(0,12);return`koschei-${state.platform}-${target}.${ext}`;}
function saveVideo(payload){if(!state.videoBlob)return;const ext=state.videoBlob.type.includes('mp4')?'mp4':'webm';window.KoscheiARVISPremium.downloadBlob(state.videoBlob,fileName(payload,ext));}
async function shareVideo(payload){if(!state.videoBlob)return;const ext=state.videoBlob.type.includes('mp4')?'mp4':'webm';const file=new File([state.videoBlob],fileName(payload,ext),{type:state.videoBlob.type||'video/webm'});const pack=currentPack();if(navigator.canShare?.({files:[file]})){try{await navigator.share({files:[file],title:pack.title,text:[pack.caption,formatTags(pack.hashtags,'#'),formatTags(pack.mentions,'@')].filter(Boolean).join('\n\n')});return;}catch(error){if(error.name==='AbortError')return;}}await copyText(packText());alert('Bu tarayıcı dosya paylaşımını desteklemiyor. Yayın paketi panoya kopyalandı.');}
async function downloadImage(payload){if(!payload)return;const api=window.KoscheiARVISPremium,format=PLATFORMS[state.platform]?.format||'tiktok',blob=await api.canvasBlob(payload,format);api.downloadBlob(blob,`koschei-${state.platform}-${String(payload.target||payload.mint||'result').slice(0,12)}.png`);}
function packText(){const pack=currentPack();return[pack.title,pack.caption,pack.description,formatTags(pack.hashtags,'#'),formatTags(pack.mentions,'@'),pack.voiceover?`VOICEOVER:\n${pack.voiceover}`:''].filter(Boolean).join('\n\n');}
async function copyText(text){try{await navigator.clipboard.writeText(String(text||''));}catch{}}

window.addEventListener('koschei:open-social-studio',event=>activate(event.detail?.payload,event.detail?.platform));
const boot=setInterval(()=>{ensureNav();if(window.KoscheiARVISPremium&&window.KoscheiOwner){clearInterval(boot);ensurePage();ensureNav();}},100);setTimeout(()=>clearInterval(boot),15000);
})();