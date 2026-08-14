(()=>{
  'use strict';

  if(window.__ownerActorDistributionInstalled)return;
  window.__ownerActorDistributionInstalled=true;

  const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  const arr=value=>Array.isArray(value)?value:[];
  const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
  const num=value=>new Intl.NumberFormat('tr-TR',{maximumFractionDigits:6}).format(Number(value||0));
  const dt=value=>{if(!value)return'—';const date=new Date(value);return Number.isNaN(date.getTime())?'—':new Intl.DateTimeFormat('tr-TR',{dateStyle:'short',timeStyle:'short'}).format(date)};
  const short=(value,length=38)=>{const text=String(value||'');return text.length>length?`${text.slice(0,length-10)}…${text.slice(-7)}`:text||'—'};
  const roleIncludes=(token,role)=>arr(token?.roles).includes(role);
  const keyFor=(creator,mint)=>`${creator}:${mint}`;
  const runs=new Map();
  let currentDossierKey='';
  let queueGeneration=0;
  let queueRunning=false;

  function ensurePanel(){
    const result=document.getElementById('ownerRadarResult');
    if(!result)return null;
    let panel=document.getElementById('ownerDistributionPanel');
    if(panel)return panel;
    panel=document.createElement('article');
    panel.id='ownerDistributionPanel';
    panel.className='card section-gap';
    panel.innerHTML='<div class="card-head"><div><span class="eyebrow">MINT-SPECIFIC ATA DISTRIBUTION</span><h2>Manuel recipient araştırması</h2><p class="muted">Otomatik tarama kapalıdır. RPC yalnız owner düğmeye bastığında ve yalnız ilgili mint için kullanılır.</p></div></div><div id="ownerDistributionContent" class="section-gap"><div class="empty">Wallet dossier bekleniyor.</div></div>';
    result.appendChild(panel);
    return panel;
  }

  function statusBadge(status){
    const normalized=String(status||'').toLowerCase();
    const css=['initial_recipients_resolved','verified','current_balance_observed'].includes(normalized)?'ok':['rpc_failed','invalid_target'].includes(normalized)?'bad':'warn';
    return`<span class="badge ${css}">${esc(String(status||'unknown').replaceAll('_',' ').toUpperCase())}</span>`;
  }

  function fateLabel(value){
    return({became_top_holder:'TOP HOLDER OLDU',still_holds:'HÂLÂ TUTUYOR',zero_balance:'BAKİYE SIFIR',exited_or_account_closed:'ÇIKTI / ATA KAPALI',current_balance_unresolved:'GÜNCEL BAKİYE ÇÖZÜLEMEDİ'}[String(value||'')]||String(value||'unknown').replaceAll('_',' ').toUpperCase());
  }

  function renderRecipientRows(report){
    const recipients=arr(report.recipients);
    if(!recipients.length)return'<div class="empty">Creator token hesaplarından doğrulanmış recipient transferi gözlemlenmedi.</div>';
    return`<div class="table-wrap"><table class="table"><thead><tr><th># / recipient</th><th>İlk gözlenen transfer</th><th>Güncel mint bakiyesi</th><th>Top-holder eşleşmesi</th><th>Kanıt</th></tr></thead><tbody>${recipients.map(recipient=>`<tr><td><b>#${num(recipient.sequence)}</b><div class="mono">${esc(short(recipient.wallet,36))}</div><div class="muted small">${esc(fateLabel(recipient.fate))}</div></td><td><b>${num(recipient.amount)} token</b>${recipient.raw_amount?`<div class="mono muted small">raw ${esc(short(recipient.raw_amount,24))}</div>`:''}<div class="muted small">${dt(recipient.observed_at)}</div></td><td><b>${num(recipient.current_balance)}</b><div class="muted small">${esc(String(recipient.current_balance_status||'').replaceAll('_',' '))}</div></td><td>${recipient.matches_top_holder?`<span class="badge bad">TOP #${num(recipient.top_holder_rank)}</span><div class="muted small">${num(recipient.top_holder_percentage)}%</div>`:'<span class="muted">Top-20 owner eşleşmesi yok</span>'}</td><td>${recipient.signature?`<a class="mono" href="https://solscan.io/tx/${encodeURIComponent(recipient.signature)}" target="_blank" rel="noopener noreferrer">${esc(short(recipient.signature,28))}</a>`:'—'}<div class="muted small">slot ${num(recipient.slot)} · ${esc(recipient.program||'')}</div></td></tr>`).join('')}</tbody></table></div>`;
  }

  function renderReport(run){
    const target=obj(run.target),report=obj(run.report),persistence=obj(run.persistence);
    const complete=report.history_complete===true;
    return`<details class="owner-details section-gap" open><summary><span><b>${esc(short(target.mint||report.mint,40))}</b><small>${esc(complete?'ATA geçmişi tamamlandı — initial recipient semantiği geçerli':'ATA geçmişi sınırlı — yalnız taranan pencere iddiası')}</small></span><span>${statusBadge(report.status)}</span></summary><div class="metadata section-gap"><div><label>Creator</label><b class="mono">${esc(short(target.creator_wallet||report.creator_wallet,34))}</b></div><div><label>Scope</label><b>${esc(String(report.distribution_scope||'').replaceAll('_',' ').toUpperCase())}</b></div><div><label>Kaynak ATA</label><b>${num(arr(report.source_token_accounts).length)}</b></div><div><label>İmzalar / tx</label><b>${num(report.signatures_scanned)} / ${num(report.transactions_parsed)}</b></div><div><label>Recipient balance sorgusu</label><b>${num(report.recipient_balance_queries)}</b></div><div><label>Kalıcı kanıt</label><b>${num(persistence.evidence_persisted)} · hata ${num(persistence.failures)}</b></div></div><div class="section-gap">${renderRecipientRows(report)}</div>${arr(report.limitations).length?`<div class="warning-box section-gap"><b>Kapsam sınırları</b><br>${arr(report.limitations).map(esc).join(' · ')}</div>`:''}</details>`;
  }

  function bindQueueActions(){
    document.querySelectorAll('[data-distribution-run]').forEach(button=>button.onclick=()=>runMint(button.dataset.distributionRun));
    document.querySelectorAll('[data-distribution-retry]').forEach(button=>button.onclick=()=>runMint(button.dataset.distributionRetry));
    document.querySelectorAll('[data-distribution-run-all]').forEach(button=>button.onclick=()=>runPending());
  }

  function renderQueue(state){
    const content=document.getElementById('ownerDistributionContent');
    if(!content)return;
    const items=arr(state.items);
    const complete=items.filter(item=>item.status==='complete').length;
    const running=items.filter(item=>item.status==='running').length;
    const failed=items.filter(item=>item.status==='failed').length;
    const pending=items.filter(item=>item.status==='pending').length;
    const manualButton=pending>0&&!queueRunning?`<button class="btn small" type="button" data-distribution-run-all>Bekleyen ${num(pending)} minti manuel tara</button>`:'';
    content.innerHTML=`<div class="card-head"><div class="metadata"><div><label>Creator mint</label><b>${num(items.length)}</b></div><div><label>Tamamlandı</label><b>${num(complete)}</b></div><div><label>Bekliyor</label><b>${num(pending)}</b></div><div><label>Çalışıyor</label><b>${num(running)}</b></div><div><label>Hata</label><b>${num(failed)}</b></div><div><label>Otomatik RPC</label><b>KAPALI</b></div></div><div>${manualButton}</div></div>${items.map(item=>{
      if(item.status==='complete')return renderReport(item.data);
      if(item.status==='failed')return`<div class="error-state section-gap"><div><b>${esc(short(item.mint,40))}</b><span>${esc(item.error||'Recipient investigation başarısız oldu.')}</span></div><button class="btn small" type="button" data-distribution-retry="${esc(item.mint)}">Manuel tekrar dene</button></div>`;
      if(item.status==='running')return`<div class="card loading section-gap">${esc(short(item.mint,40))} için owner tarafından başlatılan mint-spesifik araştırma çalışıyor…</div>`;
      return`<div class="card section-gap"><div class="card-head"><div><b>${esc(short(item.mint,40))}</b><div class="muted">Otomatik taranmaz; owner onayı bekliyor.</div></div><button class="btn small" type="button" data-distribution-run="${esc(item.mint)}">Bu minti manuel tara</button></div></div>`;
    }).join('')||'<div class="empty">Creator rolünde mint bulunmadı.</div>'}<div class="warning-box section-gap"><b>Otomatik tarama kapalı</b><br>Dossier açılması RPC çağrısı başlatmaz. Recipient başına full wallet history de hiçbir durumda çağrılmaz; yalnız owner tarafından seçilen mintin creator ATA geçmişi ve aynı-mint recipient bakiyesi sorgulanır.</div>`;
    bindQueueActions();
  }

  let queueState={creator:'',network:'solana-mainnet',items:[]};

  async function requestDistribution(creator,mint,network,generation){
    const item=queueState.items.find(entry=>entry.mint===mint);
    if(!item||generation!==queueGeneration||item.status==='running')return;
    item.status='running';
    item.error='';
    renderQueue(queueState);
    const controller=new AbortController();
    const timer=setTimeout(()=>controller.abort(),180000);
    try{
      const response=await originalFetch('/api/owner/defense/distribution',{method:'POST',credentials:'same-origin',signal:controller.signal,headers:{'Content-Type':'application/json'},body:JSON.stringify({creator_wallet:creator,mint,network})});
      let payload={};
      try{payload=await response.json();}catch{}
      if(!response.ok||payload.ok===false)throw new Error(payload.message||payload.detail||payload.error||`İstek başarısız (${response.status})`);
      if(generation!==queueGeneration)return;
      item.status='complete';
      item.data=payload;
      runs.set(keyFor(creator,mint),payload);
    }catch(error){
      if(generation!==queueGeneration)return;
      item.status='failed';
      item.error=error?.name==='AbortError'?'Recipient investigation 180 saniyede tamamlanamadı.':(error?.message||'Recipient investigation başarısız oldu.');
    }finally{
      clearTimeout(timer);
      if(generation===queueGeneration)renderQueue(queueState);
    }
  }

  async function runPending(){
    if(queueRunning)return;
    queueRunning=true;
    renderQueue(queueState);
    const generation=queueGeneration;
    try{
      for(const item of queueState.items){
        if(generation!==queueGeneration)return;
        if(item.status!=='pending')continue;
        const cached=runs.get(keyFor(queueState.creator,item.mint));
        if(cached){item.status='complete';item.data=cached;renderQueue(queueState);continue;}
        await requestDistribution(queueState.creator,item.mint,queueState.network,generation);
      }
    }finally{
      queueRunning=false;
      if(generation===queueGeneration)renderQueue(queueState);
    }
  }

  function runMint(mint){
    const item=queueState.items.find(entry=>entry.mint===mint);
    if(!item)return;
    const cached=runs.get(keyFor(queueState.creator,mint));
    if(cached){item.status='complete';item.data=cached;renderQueue(queueState);return;}
    requestDistribution(queueState.creator,mint,queueState.network,queueGeneration);
  }

  function handleDossier(payload){
    payload=obj(payload);
    const dossier=obj(payload.dossier);
    const creator=String(payload.wallet||dossier.wallet||'');
    const network=String(payload.network||dossier.network||'solana-mainnet');
    const tokens=arr(dossier.tokens).filter(token=>roleIncludes(token,'creator_deployer')&&String(token.mint||''));
    const dossierKey=`${creator}:${tokens.map(token=>token.mint).sort().join(',')}`;
    if(!creator||dossierKey===currentDossierKey)return;
    currentDossierKey=dossierKey;
    queueGeneration++;
    queueRunning=false;
    queueState={creator,network,items:tokens.map(token=>{
      const mint=String(token.mint);
      const cached=runs.get(keyFor(creator,mint));
      return{mint,status:cached?'complete':'pending',data:cached||null,error:''};
    })};
    ensurePanel();
    renderQueue(queueState);
  }

  const originalFetch=window.fetch.bind(window);
  window.fetch=async function(input,init){
    const response=await originalFetch(input,init);
    try{
      const url=typeof input==='string'?input:String(input?.url||'');
      if(url.includes('/api/owner/defense/investigate')&&response.ok){
        response.clone().json().then(payload=>handleDossier(payload)).catch(()=>{});
      }
    }catch{}
    return response;
  };

  window.addEventListener('koschei:actor-dossier',event=>handleDossier(event.detail));
})();
