(()=>{
'use strict';

const STORAGE_KEY='koschei.owner.x-publishing.v2';
const DEFAULT_SETTINGS={language:'en',includeMentions:false,autoPrepare:true,shared:{}};
const state={data:null,items:[],settings:loadSettings(),selected:null,refreshing:false,timer:null,blobCache:new Map(),urlCache:new Map()};
const owner=()=>window.KoscheiOwner;
const $=id=>document.getElementById(id);
const arr=value=>Array.isArray(value)?value:[];
const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
const first=(...values)=>values.find(value=>value!==undefined&&value!==null&&String(value).trim()!=='');
const finite=value=>Number.isFinite(Number(value))?Number(value):0;
const shorten=(value,head=8,tail=6)=>{const text=String(value||'');return text.length>head+tail+3?`${text.slice(0,head)}…${text.slice(-tail)}`:text||'—'};
const dateText=value=>{if(!value)return'—';const date=new Date(value);return Number.isNaN(date.getTime())?'—':new Intl.DateTimeFormat('tr-TR',{dateStyle:'short',timeStyle:'short'}).format(date)};

function loadSettings(){
  try{return{...DEFAULT_SETTINGS,...obj(JSON.parse(localStorage.getItem(STORAGE_KEY)||'{}'))}}
  catch{return{...DEFAULT_SETTINGS}}
}
function saveSettings(){localStorage.setItem(STORAGE_KEY,JSON.stringify(state.settings))}
function compactUSD(value){
  const number=finite(value);
  if(number<=0)return'$0';
  return new Intl.NumberFormat('en-US',{style:'currency',currency:'USD',notation:number>=1000?'compact':'standard',maximumFractionDigits:number<1?6:1}).format(number);
}
function fullUSD(value){
  const number=finite(value);
  if(number<=0)return'$0';
  return new Intl.NumberFormat('en-US',{style:'currency',currency:'USD',maximumFractionDigits:number<1?8:2}).format(number);
}
function textSignal(source,...keys){
  const root=obj(source),signals=obj(root.signals);
  for(const key of keys){
    const value=first(root[key],signals[key]);
    if(value!==undefined&&value!==null&&String(value).trim()!=='')return String(value).trim();
  }
  return'';
}
function numberSignal(source,...keys){
  const root=obj(source),signals=obj(root.signals);
  for(const key of keys){
    const value=first(root[key],signals[key]);
    if(value!==undefined&&value!==null&&value!==''&&Number.isFinite(Number(value)))return Number(value);
  }
  return 0;
}
function boolSignal(source,...keys){
  const value=textSignal(source,...keys).toLowerCase();
  return value==='true'||value==='1'||value==='yes';
}
function normalizeEvidence(...sources){
  const output=[];
  for(const source of sources){
    for(const value of arr(obj(source).evidence)){
      const line=String(value||'').trim();
      if(line&&!output.includes(line))output.push(line);
    }
    const triggered=arr(obj(obj(source).signals).triggered_rules);
    for(const value of triggered){
      const line=String(value||'').trim();
      if(line&&!output.includes(line))output.push(line);
    }
  }
  return output.slice(0,8);
}
function isAutomaticVerdict(item){
  const source=textSignal(item,'source','provider','event_type').toLowerCase();
  return boolSignal(item,'auto_volume_gate','automatic_scanning','auto_scan_attempted')||source.includes('pump_high_volume')||source.includes('automatic');
}
function mergeAutomaticItems(payload){
  const data=obj(payload),verdicts=arr(data.items),highVolume=arr(data.high_volume_pump);
  const latestVerdict=new Map();
  for(const row of verdicts){
    const target=textSignal(row,'target');
    if(!target)continue;
    const previous=latestVerdict.get(target);
    const stamp=new Date(first(row.created_at,row.report_at,0)).getTime()||0;
    const previousStamp=previous?new Date(first(previous.created_at,previous.report_at,0)).getTime()||0:-1;
    if(!previous||stamp>=previousStamp)latestVerdict.set(target,row);
  }
  const records=[];
  const used=new Set();
  for(const raw of highVolume){
    const target=textSignal(raw,'target');
    if(!target||used.has(target))continue;
    used.add(target);
    records.push(normalizeItem(raw,latestVerdict.get(target)));
  }
  for(const raw of verdicts){
    const target=textSignal(raw,'target');
    if(!target||used.has(target)||!isAutomaticVerdict(raw))continue;
    used.add(target);
    records.push(normalizeItem({},raw));
  }
  return records.sort((a,b)=>{
    const dateDiff=(new Date(b.createdAt).getTime()||0)-(new Date(a.createdAt).getTime()||0);
    return dateDiff||severityRank(b)-severityRank(a)||b.volume24h-a.volume24h;
  });
}
function normalizeItem(report,verdict){
  const r=obj(report),v=obj(verdict),signals={...obj(v.signals),...obj(r.signals)};
  const target=first(textSignal(r,'target'),textSignal(v,'target'))||'';
  const symbol=(first(textSignal(r,'symbol','token_symbol'),textSignal(v,'symbol','token_symbol'))||'TOKEN').replace(/^\$/,'').toUpperCase();
  const reportStatus=first(textSignal(r,'report_status'),textSignal(v,'report_status'),v.signed?'completed':'evidence_pending')||'evidence_pending';
  const signed=Boolean(v.signed)||String(reportStatus).toLowerCase()==='completed';
  const grade=(first(textSignal(v,'grade'),textSignal(r,'grade'))||'—').toUpperCase();
  const riskLevel=(first(textSignal(v,'risk_level'),textSignal(r,'risk_level'),signed?'evidence_backed':'watch')||'watch').toLowerCase();
  return{
    id:first(textSignal(r,'event_id','id'),textSignal(v,'event_id','id'),target)||target,
    target,
    symbol,
    name:first(textSignal(r,'name','token_name'),textSignal(v,'name','token_name'),symbol)||symbol,
    creator:first(textSignal(r,'creator','creator_wallet'),textSignal(v,'creator','creator_wallet'))||'',
    grade,
    riskLevel,
    verdict:first(textSignal(v,'verdict'),textSignal(r,'verdict'),signed?'Deterministic evidence verdict completed.':'Automatic threshold detected; evidence report pending.')||'',
    signed,
    reportStatus,
    ruleVersion:first(textSignal(v,'rule_version','ruleset_version'),textSignal(r,'rule_version','ruleset_version'))||'v1.0',
    evidence:normalizeEvidence(v,r),
    volume24h:first(numberSignal(r,'volume_24h_usd'),numberSignal(v,'volume_24h_usd'))||numberSignal({signals},'volume_24h_usd'),
    liquidity:first(numberSignal(r,'liquidity_usd'),numberSignal(v,'liquidity_usd'))||numberSignal({signals},'liquidity_usd'),
    marketCap:first(numberSignal(r,'market_cap_usd'),numberSignal(v,'market_cap_usd'))||numberSignal({signals},'market_cap_usd'),
    price:first(numberSignal(r,'price_usd'),numberSignal(v,'price_usd'))||numberSignal({signals},'price_usd'),
    threshold:first(numberSignal(r,'threshold_usd','volume_threshold_usd'),numberSignal(v,'threshold_usd','volume_threshold_usd'))||500000,
    pairCount:first(numberSignal(r,'pair_count','volume_pair_count'),numberSignal(v,'pair_count','volume_pair_count'))||0,
    holders:numberSignal({signals},'holder_count','holders','owner_count'),
    topHolderPct:numberSignal({signals},'top_holder_percentage','top_owner_percentage','dominant_holder_percentage'),
    creatorTokenCount:numberSignal({signals},'creator_token_count','creator_created_mints','created_mint_count','candidates_verified'),
    liquidCreated:numberSignal({signals},'liquid_candidates','creator_liquid_tokens'),
    inactiveCreated:numberSignal({signals},'inactive_or_dead_candidates','creator_inactive_tokens'),
    source:first(textSignal(r,'volume_provider','source'),textSignal(v,'source','provider'),'ARVIS automatic radar')||'ARVIS automatic radar',
    createdAt:first(r.report_at,r.observed_at,v.created_at,r.created_at,new Date().toISOString()),
    network:first(textSignal(v,'network'),textSignal(r,'network'),'solana-mainnet')||'solana-mainnet',
    signals
  };
}
function severityRank(item){
  const grade=String(item.grade||'').toUpperCase(),risk=String(item.riskLevel||'').toLowerCase();
  if(grade==='F'||grade==='D'||risk==='critical'||risk==='high')return 4;
  if(grade==='C'||risk==='medium')return 3;
  if(grade==='B'||risk==='low')return 2;
  return 1;
}
function tone(item){
  const rank=severityRank(item);
  return rank>=4?'critical':rank===3?'medium':item.signed?'low':'watch';
}
function displayGrade(item){return item.signed&&item.grade&&item.grade!=='—'?item.grade:'WATCH'}
function conciseVerdict(item){
  const raw=String(item.verdict||'').replace(/\s+/g,' ').trim();
  if(!raw)return item.signed?'Signed deterministic verdict completed.':'Evidence report pending.';
  return raw.length>180?`${raw.slice(0,177)}…`:raw;
}
function creatorOutcome(item){
  const total=finite(item.creatorTokenCount),liquid=finite(item.liquidCreated),inactive=finite(item.inactiveCreated);
  if(total>0&&(liquid>0||inactive>0))return`${total} verified · ${liquid} liquid · ${inactive} inactive`;
  if(total>0)return`${total} verified launches`;
  return'';
}
function cashtag(item){
  const symbol=String(item.symbol||'').replace(/[^A-Z0-9]/gi,'').slice(0,12);
  return symbol.length>=2?`$${symbol.toUpperCase()}`:'';
}
function hashtags(item){
  const tags=['#Solana','#OnChain','#ARVIS','#Web3Security'];
  if(String(item.target||'').toLowerCase().endsWith('pump'))tags.splice(2,0,'#PumpFun');
  return tags.slice(0,5).join(' ');
}
function buildCaption(item,language=state.settings.language,includeMentions=state.settings.includeMentions){
  const tag=cashtag(item),grade=displayGrade(item),risk=String(item.riskLevel||'watch').toUpperCase();
  const market=[item.liquidity>0?`Liq ${compactUSD(item.liquidity)}`:'Liq $0',item.volume24h>0?`Vol24h ${compactUSD(item.volume24h)}`:'',item.marketCap>0?`MC ${compactUSD(item.marketCap)}`:''].filter(Boolean).join(' · ');
  const creator=creatorOutcome(item);
  const mentions=includeMentions?(String(item.target||'').toLowerCase().endsWith('pump')?'@solana @pumpdotfun':'@solana'):'';
  let lines;
  if(language==='tr'){
    lines=item.signed?[
      `KOSCHEI ARVIS OTOMATİK TARAMA · ${tag||item.symbol}`,
      `Deterministik verdict: ${grade} · ${risk}`,
      market,
      creator?`Creator geçmişi: ${creator}`:'',
      `Kanıt odaklı zincir üstü istihbarat · ruleset ${item.ruleVersion}.`,
      'Finansal tavsiye veya gerçek kimlik iddiası değildir.',
      mentions,
      hashtags(item)
    ]:[
      `ARVIS OTOMATİK İZLEME · ${tag||item.symbol}`,
      `24s hacim ${compactUSD(item.volume24h)} otomatik eşiği geçti. Tam kanıt raporu bekleniyor.`,
      market,
      'İzleme sinyalidir; doğrulanmış suçlama değildir.',
      mentions,
      hashtags(item)
    ];
  }else{
    lines=item.signed?[
      `KOSCHEI ARVIS AUTO SCAN · ${tag||item.symbol}`,
      `Deterministic verdict: ${grade} · ${risk}`,
      market,
      creator?`Creator history: ${creator}`:'',
      `Evidence-first on-chain intelligence · ruleset ${item.ruleVersion}.`,
      'Not financial advice or a real-world identity claim.',
      mentions,
      hashtags(item)
    ]:[
      `ARVIS AUTO WATCH · ${tag||item.symbol}`,
      `24h volume ${compactUSD(item.volume24h)} crossed the automatic threshold. Full evidence report pending.`,
      market,
      'Watch signal only; no verified wrongdoing claim.',
      mentions,
      hashtags(item)
    ];
  }
  lines=lines.filter(Boolean);
  let caption=lines.join('\n');
  const removable=[creator?lines.findIndex(line=>line.includes(creator)):-1,lines.findIndex(line=>line.startsWith('Not financial')||line.startsWith('Finansal')),lines.findIndex(line=>line.startsWith('Evidence-first')||line.startsWith('Kanıt odaklı'))].filter(index=>index>=0).sort((a,b)=>b-a);
  for(const index of removable){
    if(caption.length<=280)break;
    lines.splice(index,1);
    caption=lines.join('\n');
  }
  if(caption.length>280){
    const finalTags=lines.pop()||'';
    caption=`${lines.join('\n').slice(0,Math.max(0,276-finalTags.length)).trimEnd()}…\n${finalTags}`;
  }
  return caption.slice(0,280);
}

function ensurePage(){
  let page=$('page-publishing');
  if(page)return page;
  page=document.createElement('section');
  page.className='page';
  page.id='page-publishing';
  page.innerHTML='<div id="publishingContent"></div>';
  const main=document.querySelector('.owner-app>.main');
  if(main)main.appendChild(page);
  return page;
}
function makeNavButton(mobile=false){
  const button=document.createElement('button');
  button.type='button';
  button.dataset.publishingNav='1';
  button.className=mobile?'':'nav-item';
  button.innerHTML=mobile?'<span>𝕏</span>Yayın':`<span class="nav-icon">𝕏</span><span>Yayın Merkezi</span>`;
  button.addEventListener('click',activate);
  return button;
}
function ensureNavigation(){
  const desktop=$('desktopNav'),mobile=$('mobileNav');
  if(desktop&&!desktop.querySelector('[data-publishing-nav]'))desktop.appendChild(makeNavButton(false));
  if(mobile&&!mobile.querySelector('[data-publishing-nav]'))mobile.appendChild(makeNavButton(true));
  syncNavState();
}
function syncNavState(){
  const active=Boolean($('page-publishing')?.classList.contains('active'));
  document.querySelectorAll('[data-publishing-nav]').forEach(button=>button.classList.toggle('active',active));
}
function activate(){
  const page=ensurePage();
  document.querySelectorAll('.page').forEach(section=>section.classList.toggle('active',section===page));
  document.querySelectorAll('[data-nav]').forEach(button=>button.classList.remove('active'));
  document.querySelectorAll('[data-publishing-nav]').forEach(button=>button.classList.add('active'));
  if($('pageTitle'))$('pageTitle').textContent='X Yayın Merkezi';
  if($('pageEyebrow'))$('pageEyebrow').textContent='Otomatik tarama → kanıt kartı → paylaşım';
  mount();
}
function ensureArvisLauncher(){
  const root=$('arvisContent');
  if(!root||!root.children.length||root.querySelector('[data-owner-publishing-launcher]'))return;
  const launcher=document.createElement('section');
  launcher.className='publish-launcher card';
  launcher.dataset.ownerPublishingLauncher='1';
  launcher.innerHTML='<div><span class="publish-kicker">X-ready evidence publishing</span><b>Otomatik taramanın yakaladığı her sonuç için görsel ve açıklama hazır.</b><small>Kanıt kartını üret, metni kopyala veya telefondan görsel + açıklamayı tek dokunuşla X paylaşımına gönder.</small></div><button class="btn primary" type="button">Yayın merkezini aç</button>';
  launcher.querySelector('button').addEventListener('click',activate);
  root.prepend(launcher);
}

async function mount(force=false){
  const root=$('publishingContent');
  if(!root)return;
  if(state.data&&!force){render();return}
  root.innerHTML='<div class="publish-loading"><div><b>Otomatik tarama sonuçları hazırlanıyor…</b><span>Verdict, likidite, hacim, creator geçmişi ve kanıt metni birleştiriliyor.</span></div></div>';
  await refresh(true);
}
async function refresh(initial=false){
  if(state.refreshing)return;
  state.refreshing=true;
  const root=$('publishingContent');
  try{
    const previous=new Set(state.items.map(item=>item.id));
    state.data=await owner().api('/api/owner/arvis');
    state.items=mergeAutomaticItems(state.data);
    render();
    if(!initial){
      const fresh=state.items.filter(item=>!previous.has(item.id));
      if(fresh.length)showPublishToast(`${fresh.length} yeni otomatik sonuç X kartı olarak hazırlandı.`);
    }
  }catch(error){
    if(root)root.innerHTML=`<div class="card error-state"><div><b>Yayın merkezi yüklenemedi.</b><span>${esc(error.message)}</span></div><button class="btn small" id="publishingRetry" type="button">Tekrar dene</button></div>`;
    $('publishingRetry')?.addEventListener('click',()=>refresh(true));
  }finally{state.refreshing=false}
}
function sharedCount(){return state.items.filter(item=>state.settings.shared[item.id]).length}
function readyCount(){return state.items.filter(item=>item.signed).length}
function newCount(){return state.items.filter(item=>!state.settings.shared[item.id]).length}
function render(){
  const root=$('publishingContent');
  if(!root)return;
  const items=state.items,total=items.length,ready=readyCount(),shared=sharedCount(),fresh=newCount();
  root.innerHTML=`<div class="publishing-shell">
    <section class="publish-hero">
      <div class="publish-hero-copy"><span class="publish-kicker">KOSCHEI ARVIS · X PUBLISHING ENGINE</span><h2>Her otomatik bulgu, kanıtını taşıyan paylaşılabilir bir sonuca dönüşür.</h2><p>ARVIS otomatik radarı yakalar; bu merkez sonuç kartını, İngilizce veya Türkçe açıklamayı, cashtag ve hashtag setini kendiliğinden hazırlar. İmzalı verdict dışında kesin iddia üretilmez.</p><div class="publish-hero-actions"><button class="publish-action primary" id="publishRefresh" type="button">Yeni sonuçları tara</button><button class="publish-action ghost" id="publishFirstReady" type="button" ${items.length?'':'disabled'}>İlk kartı önizle</button></div></div>
      <div class="publish-stats"><div class="publish-stat"><span>Otomatik bulgu</span><b>${total}</b><small>Tekrarsız hedef</small></div><div class="publish-stat"><span>İmzalı / hazır</span><b>${ready}</b><small>Deterministik verdict</small></div><div class="publish-stat"><span>Yeni kart</span><b>${fresh}</b><small>Paylaşım bekliyor</small></div><div class="publish-stat"><span>Paylaşım başlatıldı</span><b>${shared}</b><small>Bu cihaz kaydı</small></div></div>
    </section>
    <section class="publish-settings card"><div><span class="eyebrow">Otomasyon politikası</span><h3>Kart ve metin otomatik hazırlanır</h3><p>Tarayıcı güvenliği nedeniyle X paylaşımı kullanıcı dokunuşuyla başlar. Android’de görsel ve açıklama birlikte sistem paylaşım ekranına gider.</p></div><div class="publish-setting-controls"><label><span>Dil</span><select id="publishLanguage"><option value="en" ${state.settings.language==='en'?'selected':''}>English</option><option value="tr" ${state.settings.language==='tr'?'selected':''}>Türkçe</option></select></label><label class="publish-toggle"><input id="publishMentions" type="checkbox" ${state.settings.includeMentions?'checked':''}><span>Resmî mentionları ekle</span></label><label class="publish-toggle"><input id="publishAutoPrepare" type="checkbox" ${state.settings.autoPrepare?'checked':''}><span>Yeni bulguları otomatik hazırla</span></label></div></section>
    <div class="publish-section-head"><div><span class="eyebrow">Canlı yayın kuyruğu</span><h3>Otomatik ARVIS sonuçları</h3><p>Her kart gerçek üretim verisinden oluşturulur; sentetik metrik veya suçlama eklenmez.</p></div><span class="publish-count">${total} kart</span></div>
    <section class="publish-grid">${items.length?items.map(item=>renderTokenCard(item)).join(''):'<div class="publish-empty">Henüz otomatik radar sonucu yok. Yeni eşik geçişleri burada kendiliğinden görünecek.</div>'}</section>
    ${renderArchive(items)}
  </div>`;
  bindPublishingEvents();
}
function renderTokenCard(item){
  const risk=tone(item),sharedAt=state.settings.shared[item.id],creator=creatorOutcome(item),tag=cashtag(item);
  const tags=hashtags(item).split(' ').map(value=>`<span>${esc(value)}</span>`).join('');
  return`<article class="publish-token" data-risk="${esc(risk)}" data-publish-id="${esc(item.id)}">
    <div class="publish-token-top"><div class="publish-identity"><div class="publish-symbol"><span class="publish-symbol-mark">${esc(item.symbol.slice(0,2))}</span><span>${esc(tag||item.symbol)}</span></div><div class="publish-name">${esc(item.name)}</div><div class="publish-mint">${esc(shorten(item.target,12,9))}</div></div><div class="publish-risk ${esc(risk)}"><b>${esc(displayGrade(item))}</b><span>${esc(item.signed?item.riskLevel:'evidence pending')}</span></div></div>
    <div class="publish-visual-mini"><div class="publish-visual-grid"></div><span>KOSCHEI ARVIS</span><strong>${esc(tag||item.symbol)}</strong><em>${esc(item.signed?`VERDICT ${displayGrade(item)}`:'AUTO WATCH')}</em><small>${esc(compactUSD(item.liquidity))} liquidity · ${esc(compactUSD(item.volume24h))} 24h volume</small></div>
    <div class="publish-metrics"><div class="publish-metric"><span>Likidite</span><b>${esc(compactUSD(item.liquidity))}</b></div><div class="publish-metric"><span>24s hacim</span><b>${esc(compactUSD(item.volume24h))}</b></div><div class="publish-metric"><span>Piyasa değeri</span><b>${esc(item.marketCap>0?compactUSD(item.marketCap):'—')}</b></div></div>
    ${creator?`<div class="publish-creator-outcome"><span>Creator akıbeti</span><b>${esc(creator)}</b></div>`:''}
    <div class="publish-insight">${esc(conciseVerdict(item))}</div>
    <div class="publish-tag-row">${tags}</div>
    <div class="publish-actions"><button class="publish-action" data-publish-preview="${esc(item.id)}" type="button">Görseli önizle</button><button class="publish-action" data-publish-copy="${esc(item.id)}" type="button">Metni kopyala</button><button class="publish-action ghost" data-publish-report="${esc(item.target)}" type="button">Tam rapor</button><button class="publish-action primary" data-publish-share="${esc(item.id)}" type="button">${sharedAt?'Yeniden X’e paylaş':'X’e paylaş'}</button></div>
    <div class="publish-card-foot"><span>${esc(item.signed?`SIGNED · ${item.ruleVersion}`:'WATCH · EVIDENCE PENDING')}</span><span>${sharedAt?`Paylaşım ${esc(dateText(sharedAt))}`:`Hazır · ${esc(dateText(item.createdAt))}`}</span></div>
  </article>`;
}
function renderArchive(items){
  const shared=items.filter(item=>state.settings.shared[item.id]);
  if(!shared.length)return'';
  return`<details class="publish-archive"><summary><span>Bu cihazda paylaşımı başlatılan kartlar</span><span>${shared.length} kayıt</span></summary><div class="publish-archive-list">${shared.map(item=>`<div class="publish-history-row"><b>${esc(cashtag(item)||item.symbol)} · ${esc(shorten(item.target,10,7))}</b><span>${esc(displayGrade(item))}</span><span>${esc(dateText(state.settings.shared[item.id]))}</span></div>`).join('')}</div></details>`;
}
function bindPublishingEvents(){
  $('publishRefresh')?.addEventListener('click',()=>refresh(false));
  $('publishFirstReady')?.addEventListener('click',()=>state.items[0]&&openPreview(state.items[0]));
  $('publishLanguage')?.addEventListener('change',event=>{state.settings.language=event.target.value;saveSettings();render()});
  $('publishMentions')?.addEventListener('change',event=>{state.settings.includeMentions=event.target.checked;saveSettings()});
  $('publishAutoPrepare')?.addEventListener('change',event=>{state.settings.autoPrepare=event.target.checked;saveSettings()});
  document.querySelectorAll('[data-publish-preview]').forEach(button=>button.addEventListener('click',()=>openPreview(findItem(button.dataset.publishPreview))));
  document.querySelectorAll('[data-publish-copy]').forEach(button=>button.addEventListener('click',()=>copyCaption(findItem(button.dataset.publishCopy))));
  document.querySelectorAll('[data-publish-share]').forEach(button=>button.addEventListener('click',()=>shareItem(findItem(button.dataset.publishShare))));
  document.querySelectorAll('[data-publish-report]').forEach(button=>button.addEventListener('click',()=>openFullReport(button.dataset.publishReport)));
}
function findItem(id){return state.items.find(item=>item.id===id)||null}

async function copyText(value){
  if(navigator.clipboard?.writeText){await navigator.clipboard.writeText(value);return}
  const area=document.createElement('textarea');area.value=value;area.style.position='fixed';area.style.opacity='0';document.body.appendChild(area);area.select();document.execCommand('copy');area.remove();
}
async function copyCaption(item){
  if(!item)return;
  await copyText(buildCaption(item));
  showPublishToast('X açıklaması panoya kopyalandı.');
}
function showPublishToast(message,bad=false){
  document.querySelector('.publish-toast')?.remove();
  const toast=document.createElement('div');toast.className=`publish-toast${bad?' bad':''}`;toast.textContent=message;document.body.appendChild(toast);setTimeout(()=>toast.remove(),4200);
}
function openFullReport(target){
  document.querySelector('[data-nav="arvis"]')?.click();
  let attempts=0;
  const wait=setInterval(()=>{
    attempts++;
    const input=$('ownerRadarTarget'),result=$('ownerRadarResult');
    if(input&&result&&window.OwnerRadarKit?.scan){clearInterval(wait);input.value=target;window.OwnerRadarKit.scan(target,'ownerRadarResult');return}
    if(attempts>80){clearInterval(wait);showPublishToast('Tam rapor paneli açılamadı.',true)}
  },100);
}
async function openPreview(item){
  if(!item)return;
  state.selected=item;
  const modalRoot=$('modalRoot')||document.body;
  modalRoot.innerHTML=`<div class="publish-modal-backdrop" data-publish-close-area><section class="publish-modal" role="dialog" aria-modal="true"><header class="publish-modal-head"><div><b>${esc(cashtag(item)||item.symbol)} · X sonuç kartı</b><span>${esc(shorten(item.target,16,12))}</span></div><button class="publish-close" data-publish-close type="button">×</button></header><div class="publish-modal-body"><div class="publish-studio"><div class="publish-preview-frame"><div class="publish-loading" id="publishPreviewLoading"><div><b>1600 × 900 kanıt kartı üretiliyor…</b><span>Görsel gerçek tarama verisinden çiziliyor.</span></div></div><img id="publishPreviewImage" alt="ARVIS X paylaşım kartı"></div><div class="publish-copy-panel"><span class="eyebrow">Otomatik açıklama</span><textarea id="publishCaptionEditor" maxlength="280">${esc(buildCaption(item))}</textarea><div class="publish-character-count"><span>Cashtag + hashtag otomatik</span><b id="publishCaptionCount">${buildCaption(item).length}/280</b></div><div class="publish-proof"><div><span>Verdict</span><b>${esc(displayGrade(item))} · ${esc(item.riskLevel.toUpperCase())}</b></div><div><span>Likidite</span><b>${esc(fullUSD(item.liquidity))}</b></div><div><span>24s hacim</span><b>${esc(fullUSD(item.volume24h))}</b></div><div><span>Ruleset</span><b>${esc(item.ruleVersion)}</b></div></div><div class="publish-modal-actions"><button class="publish-action" id="publishModalCopy" type="button">Metni kopyala</button><button class="publish-action" id="publishModalDownload" type="button">PNG indir</button><button class="publish-action primary" id="publishModalShare" type="button">Görsel + metni X’e gönder</button></div><p class="publish-share-note">Android’de sistem paylaşım ekranı görseli ve metni birlikte taşır. Masaüstünde PNG indirilir, metin kopyalanır ve X gönderi ekranı açılır.</p></div></div></div></section></div>`;
  const close=()=>{revokeSelectedPreview();if(modalRoot!==document.body)modalRoot.innerHTML='';else document.querySelector('.publish-modal-backdrop')?.remove()};
  document.querySelector('[data-publish-close]')?.addEventListener('click',close);
  document.querySelector('[data-publish-close-area]')?.addEventListener('click',event=>{if(event.target.hasAttribute('data-publish-close-area'))close()});
  const editor=$('publishCaptionEditor'),counter=$('publishCaptionCount');
  editor?.addEventListener('input',()=>{if(counter)counter.textContent=`${editor.value.length}/280`});
  $('publishModalCopy')?.addEventListener('click',async()=>{await copyText(editor.value);showPublishToast('Düzenlenen açıklama kopyalandı.')});
  $('publishModalDownload')?.addEventListener('click',()=>downloadItem(item));
  $('publishModalShare')?.addEventListener('click',()=>shareItem(item,editor.value));
  try{
    const blob=await cardBlob(item),url=URL.createObjectURL(blob);state.previewURL=url;
    if($('publishPreviewImage')){$('publishPreviewImage').src=url;$('publishPreviewImage').classList.add('ready')}
    $('publishPreviewLoading')?.remove();
  }catch(error){if($('publishPreviewLoading'))$('publishPreviewLoading').innerHTML=`<div><b>Görsel üretilemedi.</b><span>${esc(error.message)}</span></div>`}
}
function revokeSelectedPreview(){if(state.previewURL){URL.revokeObjectURL(state.previewURL);state.previewURL=''}}
async function cardBlob(item){
  if(state.blobCache.has(item.id))return state.blobCache.get(item.id);
  const canvas=renderEvidenceCanvas(item);
  const blob=await new Promise((resolve,reject)=>canvas.toBlob(value=>value?resolve(value):reject(new Error('PNG encoder unavailable')),'image/png',0.96));
  state.blobCache.set(item.id,blob);
  if(state.blobCache.size>18){const oldest=state.blobCache.keys().next().value;state.blobCache.delete(oldest)}
  return blob;
}
async function downloadItem(item){
  if(!item)return;
  const blob=await cardBlob(item),url=URL.createObjectURL(blob),link=document.createElement('a');
  link.href=url;link.download=`koschei-arvis-${String(item.symbol||'token').toLowerCase()}-${String(item.target||'scan').slice(0,8)}.png`;document.body.appendChild(link);link.click();link.remove();setTimeout(()=>URL.revokeObjectURL(url),2000);showPublishToast('1600 × 900 PNG hazırlandı.');
}
async function shareItem(item,customCaption=''){
  if(!item)return;
  try{
    const caption=String(customCaption||buildCaption(item)).slice(0,280),blob=await cardBlob(item),filename=`koschei-arvis-${String(item.symbol||'token').toLowerCase()}.png`,file=new File([blob],filename,{type:'image/png'});
    if(navigator.share&&(!navigator.canShare||navigator.canShare({files:[file]}))){
      await navigator.share({title:`KOSCHEI ARVIS · ${cashtag(item)||item.symbol}`,text:caption,files:[file]});
      markShareStarted(item);showPublishToast('Görsel ve açıklama X paylaşım akışına gönderildi.');return;
    }
    await downloadItem(item);await copyText(caption);window.open(`https://twitter.com/intent/tweet?text=${encodeURIComponent(caption)}`,'_blank','noopener,noreferrer');markShareStarted(item);showPublishToast('PNG indirildi, metin kopyalandı ve X gönderi ekranı açıldı.');
  }catch(error){if(error?.name==='AbortError')return;showPublishToast(error.message||'Paylaşım başlatılamadı.',true)}
}
function markShareStarted(item){state.settings.shared[item.id]=new Date().toISOString();saveSettings();render()}

function renderEvidenceCanvas(item){
  const canvas=document.createElement('canvas');canvas.width=1600;canvas.height=900;const ctx=canvas.getContext('2d');
  if(!ctx)throw new Error('Canvas context unavailable');
  const accent=canvasAccent(item),bg=ctx.createLinearGradient(0,0,1600,900);bg.addColorStop(0,'#02070c');bg.addColorStop(.48,'#071722');bg.addColorStop(1,'#02080d');ctx.fillStyle=bg;ctx.fillRect(0,0,1600,900);
  const glow=ctx.createRadialGradient(1180,130,10,1180,130,600);glow.addColorStop(0,hexAlpha(accent,.22));glow.addColorStop(1,hexAlpha(accent,0));ctx.fillStyle=glow;ctx.fillRect(0,0,1600,900);
  ctx.save();ctx.globalAlpha=.08;ctx.strokeStyle='#54d9ff';ctx.lineWidth=1;for(let x=0;x<=1600;x+=64){ctx.beginPath();ctx.moveTo(x,0);ctx.lineTo(x,900);ctx.stroke()}for(let y=0;y<=900;y+=64){ctx.beginPath();ctx.moveTo(0,y);ctx.lineTo(1600,y);ctx.stroke()}ctx.restore();
  drawCornerLines(ctx,accent);drawBrand(ctx,accent,item);
  ctx.fillStyle='#f4fbff';ctx.font='900 78px Arial, sans-serif';ctx.fillText(cashtag(item)||item.symbol,72,252);
  ctx.fillStyle='#91a9b8';ctx.font='600 28px Arial, sans-serif';ctx.fillText(trimCanvasText(ctx,item.name,720),76,300);
  ctx.fillStyle='#668291';ctx.font='600 21px ui-monospace, SFMono-Regular, Menlo, monospace';ctx.fillText(shorten(item.target,18,14),76,340);
  drawVerdictBlock(ctx,item,accent);
  const metrics=[['CURRENT PRICE',item.price>0?fullUSD(item.price):'—'],['LIQUIDITY',compactUSD(item.liquidity)],['24H VOLUME',compactUSD(item.volume24h)],['MARKET CAP',item.marketCap>0?compactUSD(item.marketCap):'—']];
  metrics.forEach((metric,index)=>drawMetric(ctx,72+index*374,394,350,132,metric[0],metric[1],accent));
  drawEvidencePanel(ctx,item,accent);drawFooter(ctx,item,accent);
  return canvas;
}
function canvasAccent(item){const risk=tone(item);return risk==='critical'?'#ff526f':risk==='medium'?'#ffc95c':risk==='low'?'#18ffb2':'#27d8ff'}
function hexAlpha(hex,alpha){const clean=hex.replace('#','');const value=parseInt(clean,16);return`rgba(${value>>16},${value>>8&255},${value&255},${alpha})`}
function roundedPath(ctx,x,y,w,h,r){const radius=Math.min(r,w/2,h/2);ctx.beginPath();ctx.moveTo(x+radius,y);ctx.arcTo(x+w,y,x+w,y+h,radius);ctx.arcTo(x+w,y+h,x,y+h,radius);ctx.arcTo(x,y+h,x,y,radius);ctx.arcTo(x,y,x+w,y,radius);ctx.closePath()}
function drawCornerLines(ctx,accent){ctx.save();ctx.strokeStyle=hexAlpha(accent,.45);ctx.lineWidth=2;ctx.beginPath();ctx.moveTo(0,92);ctx.lineTo(330,92);ctx.lineTo(382,40);ctx.stroke();ctx.beginPath();ctx.moveTo(1260,860);ctx.lineTo(1510,860);ctx.lineTo(1600,770);ctx.stroke();ctx.restore()}
function drawBrand(ctx,accent,item){
  ctx.save();ctx.translate(74,72);ctx.strokeStyle=accent;ctx.lineWidth=4;ctx.beginPath();for(let i=0;i<6;i++){const angle=Math.PI/3*i-Math.PI/6,x=Math.cos(angle)*30,y=Math.sin(angle)*30;i?ctx.lineTo(x,y):ctx.moveTo(x,y)}ctx.closePath();ctx.stroke();ctx.beginPath();ctx.arc(0,0,13,0,Math.PI*2);ctx.stroke();ctx.beginPath();ctx.moveTo(-13,0);ctx.lineTo(13,0);ctx.moveTo(0,-13);ctx.lineTo(0,13);ctx.stroke();ctx.restore();
  ctx.fillStyle='#f0fbff';ctx.font='900 28px Arial, sans-serif';ctx.fillText('KOSCHEI ARVIS',124,66);ctx.fillStyle=accent;ctx.font='800 15px ui-monospace, SFMono-Regular, Menlo, monospace';ctx.fillText(item.signed?'AUTO SCAN · SIGNED EVIDENCE':'AUTO WATCH · EVIDENCE PENDING',126,91);
  ctx.textAlign='right';ctx.fillStyle='#7d98a8';ctx.font='700 16px ui-monospace, SFMono-Regular, Menlo, monospace';ctx.fillText('ON-CHAIN ACTOR INTELLIGENCE',1528,62);ctx.fillStyle=accent;ctx.fillText(item.network.toUpperCase(),1528,87);ctx.textAlign='left';
}
function drawVerdictBlock(ctx,item,accent){
  const x=1190,y=160,w=338,h=176;roundedPath(ctx,x,y,w,h,26);ctx.fillStyle=hexAlpha(accent,.10);ctx.fill();ctx.strokeStyle=hexAlpha(accent,.52);ctx.lineWidth=2;ctx.stroke();ctx.fillStyle=accent;ctx.font='900 18px ui-monospace, SFMono-Regular, Menlo, monospace';ctx.fillText(item.signed?'DETERMINISTIC VERDICT':'AUTOMATIC WATCH',x+28,y+38);ctx.fillStyle='#ffffff';ctx.font='900 74px Arial, sans-serif';ctx.fillText(displayGrade(item),x+28,y+114);ctx.fillStyle='#9eb3bf';ctx.font='800 19px Arial, sans-serif';ctx.fillText(item.signed?item.riskLevel.toUpperCase():'REPORT PENDING',x+29,y+148);
}
function drawMetric(ctx,x,y,w,h,label,value,accent){roundedPath(ctx,x,y,w,h,18);ctx.fillStyle='rgba(3,13,20,.78)';ctx.fill();ctx.strokeStyle='rgba(132,196,215,.17)';ctx.lineWidth=2;ctx.stroke();ctx.fillStyle='#708b9a';ctx.font='800 15px ui-monospace, SFMono-Regular, Menlo, monospace';ctx.fillText(label,x+22,y+34);ctx.fillStyle='#f5fbff';ctx.font=value.length>14?'900 32px Arial, sans-serif':'900 38px Arial, sans-serif';ctx.fillText(trimCanvasText(ctx,value,w-44),x+22,y+91);ctx.fillStyle=accent;ctx.fillRect(x+22,y+h-16,74,3)}
function drawEvidencePanel(ctx,item,accent){
  const x=72,y=568,w=1456,h=218;roundedPath(ctx,x,y,w,h,24);ctx.fillStyle='rgba(3,13,20,.72)';ctx.fill();ctx.strokeStyle='rgba(132,196,215,.17)';ctx.lineWidth=2;ctx.stroke();ctx.fillStyle=accent;ctx.font='900 16px ui-monospace, SFMono-Regular, Menlo, monospace';ctx.fillText(item.signed?'EVIDENCE-BACKED FINDING':'AUTOMATIC THRESHOLD OBSERVATION',x+28,y+38);
  ctx.fillStyle='#dbeaf0';ctx.font='700 27px Arial, sans-serif';const main=conciseVerdict(item);wrapCanvasText(ctx,main,x+28,y+82,900,37,3);
  const creator=creatorOutcome(item);const rightX=1070;ctx.fillStyle='#718d9c';ctx.font='800 14px ui-monospace, SFMono-Regular, Menlo, monospace';ctx.fillText(creator?'CREATOR TOKEN OUTCOME':'EVIDENCE POLICY',rightX,y+38);ctx.fillStyle='#f2f9fc';ctx.font='900 24px Arial, sans-serif';wrapCanvasText(ctx,creator||'No evidence, no claim.',rightX,y+79,420,33,3);ctx.fillStyle='#7793a2';ctx.font='700 16px Arial, sans-serif';ctx.fillText(`Ruleset ${item.ruleVersion} · ${item.signed?'signed deterministic result':'watch-only state'}`,rightX,y+174);
}
function drawFooter(ctx,item,accent){ctx.strokeStyle='rgba(132,196,215,.17)';ctx.beginPath();ctx.moveTo(72,828);ctx.lineTo(1528,828);ctx.stroke();ctx.fillStyle='#7994a3';ctx.font='700 16px ui-monospace, SFMono-Regular, Menlo, monospace';ctx.fillText(`SCAN ${shorten(item.id,12,10)} · ${new Date(item.createdAt).toISOString().replace('T',' ').slice(0,19)} UTC`,72,866);ctx.textAlign='right';ctx.fillStyle=accent;ctx.font='900 17px Arial, sans-serif';ctx.fillText('EVIDENCE FIRST · NOT FINANCIAL ADVICE',1528,866);ctx.textAlign='left'}
function trimCanvasText(ctx,value,maxWidth){let text=String(value||'');if(ctx.measureText(text).width<=maxWidth)return text;while(text.length>3&&ctx.measureText(`${text}…`).width>maxWidth)text=text.slice(0,-1);return`${text}…`}
function wrapCanvasText(ctx,text,x,y,maxWidth,lineHeight,maxLines){const words=String(text||'').split(/\s+/),lines=[];let line='';for(const word of words){const test=line?`${line} ${word}`:word;if(ctx.measureText(test).width>maxWidth&&line){lines.push(line);line=word;if(lines.length===maxLines-1)break}else line=test}if(line&&lines.length<maxLines)lines.push(line);const consumed=lines.join(' ').split(/\s+/).length;if(consumed<words.length)lines[lines.length-1]=trimCanvasText(ctx,`${lines[lines.length-1]}…`,maxWidth);lines.forEach((value,index)=>ctx.fillText(value,x,y+index*lineHeight));return lines.length}

function bootstrap(){
  ensurePage();ensureNavigation();ensureArvisLauncher();
  const navObserver=new MutationObserver(()=>{ensureNavigation();ensureArvisLauncher()});
  if($('desktopNav'))navObserver.observe($('desktopNav'),{childList:true});
  if($('mobileNav'))navObserver.observe($('mobileNav'),{childList:true});
  if($('arvisContent'))navObserver.observe($('arvisContent'),{childList:true,subtree:false});
  document.addEventListener('click',event=>{if(event.target.closest('[data-nav]'))setTimeout(syncNavState,0)},true);
  state.timer=setInterval(()=>{if(state.settings.autoPrepare&&$('page-publishing')?.classList.contains('active'))refresh(false)},60000);
  window.OwnerPublishingCenter={mount,refresh,activate,buildCaption,renderEvidenceCanvas};
}
if(document.readyState==='loading')document.addEventListener('DOMContentLoaded',bootstrap,{once:true});else bootstrap();
})();
