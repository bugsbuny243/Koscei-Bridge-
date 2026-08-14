(()=>{
  'use strict';

  const kit=window.OwnerRadarKit;
  if(!kit||window.__ownerDefenseNetworkInstalled)return;
  window.__ownerDefenseNetworkInstalled=true;
  const originalScan=kit.scan.bind(kit);
  const originalRender=kit.render.bind(kit);
  const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  const arr=value=>Array.isArray(value)?value:[];
  const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
  const num=value=>new Intl.NumberFormat('tr-TR',{maximumFractionDigits:6}).format(Number(value||0));
  const dt=value=>{if(!value)return'—';const date=new Date(value);return Number.isNaN(date.getTime())?'—':new Intl.DateTimeFormat('tr-TR',{dateStyle:'short',timeStyle:'short'}).format(date)};
  const short=(value,length=36)=>{const text=String(value||'');return text.length>length?`${text.slice(0,length-10)}…${text.slice(-7)}`:text||'—'};
  const rootFor=value=>typeof value==='string'?document.getElementById(value):value;
  const stateLabel=value=>({detected:'TESPİT EDİLDİ',tracked:'TAKİPTE',correlated:'İLİŞKİLENDİRİLDİ',verified:'DOĞRULANDI',alerted:'UYARI ÜRETİLDİ'}[String(value||'').toLowerCase()]||String(value||'BİLİNMİYOR').toUpperCase());
  const bandLabel=value=>({hard_trigger:'HARD TRIGGER',compounding:'COMPOUNDING',evidence_pending:'KANIT BEKLİYOR',watch:'WATCH',verified_review:'VERIFIED REVIEW',monitor:'İZLE'}[String(value||'').toLowerCase()]||String(value||'İZLE').replaceAll('_',' ').toUpperCase());
  const actionLabel=value=>({monitor_sensor_memory:'Sensör hafızasında izle',review_verified_evidence:'Doğrulanmış kanıtı incele',review_verified_creator_holder_funding:'Creator → dominant-holder funding imzasını incele',review_verified_creator_liquidity_removal:'Creator liquidity-removal imzasını incele',review_verified_previous_token_incident:'Önceki token olay kanıtını incele',collect_live_transaction_evidence:'Canlı transaction kanıtı topla',verify_inferred_relations:'INFERRED ilişkileri zincirde doğrula',expand_cross_token_holder_network:'Cross-token holder ağını genişlet',expand_creator_token_history:'Creator token geçmişini genişlet'}[String(value||'')]||String(value||'İncele').replaceAll('_',' '));
  const statusClass=value=>{const text=String(value||'').toLowerCase();return ['verified','a','b'].includes(text)?'ok':['hard_trigger','alerted','d','e','f'].includes(text)?'bad':'warn'};
  const badge=(value,label=value)=>`<span class="badge ${statusClass(value)}">${esc(label)}</span>`;
  const kpi=(label,value,foot)=>`<article class="card kpi"><div class="kpi-top"><div><div class="kpi-label">${esc(label)}</div><div class="kpi-value tone-cyan">${esc(value)}</div></div></div><div class="kpi-foot">${esc(foot)}</div></article>`;

  function renderTokens(tokens){
    if(!tokens.length)return'<div class="empty">Koschei sensörlerinde bu cüzdana bağlı token gözlemi yok.</div>';
    return`<div class="table-wrap"><table class="table"><thead><tr><th>Mint</th><th>Roller</th><th>Holder</th><th>Pump işlemleri</th><th>İlk / son gözlem</th></tr></thead><tbody>${tokens.map(token=>`<tr><td><b>${esc(token.symbol||token.name||'Token')}</b><div class="mono">${esc(short(token.mint,34))}</div></td><td>${arr(token.roles).map(role=>badge('observed',String(role).replaceAll('_',' ').toUpperCase())).join(' ')||'—'}</td><td>${token.holder_rank?`#${num(token.holder_rank)} · ${num(token.holder_percentage)}%`:'—'}</td><td>${num(token.buy_count)} alım · ${num(token.sell_count)} satış<div class="muted small">${num(token.sol_bought)} SOL alım · ${num(token.sol_sold)} SOL satış</div></td><td>${dt(token.first_observed_at)}<br><span class="muted small">${dt(token.last_observed_at)}</span></td></tr>`).join('')}</tbody></table></div>`;
  }

  function renderActors(actors){
    if(!actors.length)return'<div class="empty">Bu token kümesinde tekrar eden owner-resolved holder henüz gözlemlenmedi.</div>';
    return`<div class="table-wrap"><table class="table"><thead><tr><th>Cüzdan</th><th>Ortak token</th><th>En yüksek holder payı</th><th>Gözlem penceresi</th></tr></thead><tbody>${actors.map(actor=>`<tr><td class="mono">${esc(short(actor.wallet,38))}</td><td><b>${num(actor.shared_token_count)}</b></td><td><b>${num(actor.max_holder_percentage)}%</b></td><td>${dt(actor.first_observed_at)} → ${dt(actor.last_observed_at)}</td></tr>`).join('')}</tbody></table></div>`;
  }

  function renderEvidence(evidence){
    if(!evidence.length)return'<div class="warning-box"><b>Doğrudan transaction bağlantısı henüz kaydedilmedi.</b><br>Bu, bağlantı olmadığı anlamına gelmez; yalnız sorgulanan imza penceresinde VERIFIED veya OBSERVED kanıt oluşmadığını gösterir.</div>';
    return`<div class="table-wrap"><table class="table"><thead><tr><th>Durum</th><th>İlişki</th><th>Karşı taraf</th><th>Miktar</th><th>İmza / zaman</th></tr></thead><tbody>${evidence.map(item=>`<tr><td>${badge(item.verification_status,String(item.verification_status||'observed').toUpperCase())}</td><td><b>${esc(String(item.relation||'').replaceAll('_',' ').toUpperCase())}</b><div class="muted small">${esc(item.source||'koschei')}</div></td><td><span class="mono">${esc(short(item.counterpart_id,34))}</span><div class="muted small">${esc(item.counterpart_kind||'')}</div></td><td>${item.amount_native?`${num(item.amount_native)} SOL`:item.token_amount?`${num(item.token_amount)} token`:'—'}${item.token_mint?`<div class="mono muted small">${esc(short(item.token_mint,25))}</div>`:''}</td><td>${item.signature?`<a class="mono" href="https://solscan.io/tx/${encodeURIComponent(item.signature)}" target="_blank" rel="noopener noreferrer">${esc(short(item.signature,30))}</a>`:'—'}<div class="muted small">${dt(item.observed_at)} · slot ${num(item.slot)}</div></td></tr>`).join('')}</tbody></table></div>`;
  }

  function renderFunding(origin){
    origin=obj(origin);
    const status=String(origin.status||'not_investigated');
    const verification=String(origin.verification_status||'unverified');
    const complete=origin.history_complete===true;
    const title=complete?'İlk funding kaynağı':'Taranan penceredeki en eski funding';
    const source=String(origin.source_wallet||'');
    const destination=String(origin.destination_wallet||origin.wallet||'');
    const hasEvidence=source&&origin.signature;
    const historyLabel=complete?'TAM GEÇMİŞ':'SINIRLI PENCERE';
    const limitations=arr(origin.limitations);
    return`<article class="card section-gap"><div class="card-head"><div><span class="eyebrow">FUNDING ORIGIN · SYSTEM PROGRAM</span><h2>${esc(hasEvidence?title:'Funding kaynağı doğrulanmadı')}</h2><p class="muted">${esc(status.replaceAll('_',' ').toUpperCase())}</p></div>${badge(verification,String(verification).toUpperCase())}</div><div class="metadata section-gap"><div><label>Geçmiş kapsamı</label><b>${esc(historyLabel)}</b></div><div><label>Kaynak wallet</label><b class="mono">${source?`<a href="https://solscan.io/account/${encodeURIComponent(source)}" target="_blank" rel="noopener noreferrer">${esc(short(source,34))}</a>`:'—'}</b></div><div><label>Hedef wallet</label><b class="mono">${destination?esc(short(destination,34)):'—'}</b></div><div><label>Miktar</label><b>${origin.amount_sol?`${num(origin.amount_sol)} SOL`:'—'}</b></div><div><label>İşlem</label><b>${esc(origin.instruction_type||'—')}</b></div><div><label>Sayfalar / imzalar</label><b>${num(origin.pages_scanned)} / ${num(origin.signatures_scanned)}</b></div></div>${origin.signature?`<div class="warning-box section-gap"><b>Kanıt satırı</b><br>Signature: <a class="mono" href="https://solscan.io/tx/${encodeURIComponent(origin.signature)}" target="_blank" rel="noopener noreferrer">${esc(short(origin.signature,38))}</a><br>Slot: ${num(origin.slot)} · Timestamp: ${esc(dt(origin.observed_at))} · Program: ${esc(origin.program||'system')} · Status: ${esc(verification.toUpperCase())}</div>`:''}<div class="warning-box section-gap"><b>Kimlik sınırı</b><br>${esc(origin.identity_scope||'onchain_wallet_only')}. Bir CEX veya gerçek kişi etiketi ayrıca doğrulanmadıkça Koschei isim/kimlik iddiası üretmez.${limitations.length?`<br><br>${limitations.map(esc).join(' · ')}`:''}</div></article>`;
  }

  function renderRuleHits(items,empty){
    if(!items.length)return`<div class="empty">${esc(empty)}</div>`;
    return`<div class="table-wrap"><table class="table"><thead><tr><th>Kural</th><th>Kanıt sınıfı</th><th>Grade etkisi</th><th>Kanıt</th></tr></thead><tbody>${items.map(hit=>`<tr><td><b>${esc(hit.rule_id)} · ${esc(hit.title)}</b><div class="muted small">${esc(hit.summary||'')}</div></td><td>${badge(hit.evidence_status,String(hit.evidence_status||'').toUpperCase())}${Number(hit.count||0)>1?` <span class="muted">×${num(hit.count)}</span>`:''}</td><td>${hit.grade_cap?`En iyi ihtimalle <b>${esc(hit.grade_cap)}</b>`:esc(hit.grade_effect||'none')}</td><td>${arr(hit.signatures).map(signature=>`<a class="mono" href="https://solscan.io/tx/${encodeURIComponent(signature)}" target="_blank" rel="noopener noreferrer">${esc(short(signature,25))}</a>`).join('<br>')||arr(hit.evidence_keys).map(key=>`<span class="mono">${esc(short(key,28))}</span>`).join('<br>')||'—'}</td></tr>`).join('')}</tbody></table></div>`;
  }

  function renderRuleVerdict(verdict){
    verdict=obj(verdict);
    const grade=String(verdict.grade||'-');
    return`<article class="card section-gap" style="border-color:#18ffb255"><div class="card-head"><div><span class="eyebrow">DETERMINISTIC RULE VERDICT</span><h2>${grade==='-'?'HARF VERDICT YOK':`GRADE ${esc(grade)}`}</h2><p class="muted">${esc(verdict.ruleset_version||'ruleset unavailable')} · ağırlıklı skor yok</p></div>${badge(verdict.verdict,grade==='-'?String(verdict.verdict||'NO GRADE').replaceAll('_',' ').toUpperCase():grade)}</div><details class="owner-details" open><summary><span><b>Tetiklenen kurallar</b><small>VERIFIED hard trigger veya VERIFIED/OBSERVED compounding girdileri.</small></span><span>⌄</span></summary><div class="section-gap">${renderRuleHits(arr(verdict.triggered_rules),'Grade değiştiren kural tetiklenmedi.')}</div></details><details class="owner-details section-gap"><summary><span><b>Watch flags</b><small>INFERRED görünür kalır ama grade’i değiştiremez.</small></span><span>⌄</span></summary><div class="section-gap">${renderRuleHits(arr(verdict.watch_flags),'INFERRED watch flag yok.')}</div></details><div class="metadata section-gap"><div><label>Ruleset</label><b>${esc(verdict.ruleset_version||'—')}</b></div><div><label>İmzalı verdict</label><b>${verdict.signed?'EVET':'HAYIR'}</b></div><div><label>Verdict signature</label><b class="mono">${esc(short(verdict.signature,32))}</b></div><div><label>UNVERIFIED dışlandı</label><b>${num(verdict.excluded_unverified_evidence)}</b></div></div><div class="warning-box section-gap"><b>Karar yolu</b><br>${arr(verdict.decision_path).map(esc).join('<br>')}</div></article>`;
  }

  function renderDefense(root,payload){
    root=rootFor(root);
    if(!root)return;
    const dossier=obj(payload.dossier),track=obj(dossier.track),coverage=obj(dossier.coverage),live=obj(coverage.live_evidence),ruleVerdict=obj(payload.rule_verdict),funding=obj(payload.funding_origin||coverage.funding_origin);
    const tokens=arr(dossier.tokens),actors=arr(dossier.related_actors),evidence=arr(dossier.evidence);
    root.innerHTML=`<div class="card" style="border-color:#18ffb255"><div class="card-head"><div><span class="eyebrow">KOSCHEI DEFENSE NETWORK · ACTOR DOSSIER</span><h2>${esc(stateLabel(track.state))}</h2><div class="mono muted">${esc(dossier.wallet||payload.wallet||payload.target)}</div></div>${badge(track.state==='verified'?'verified':'observed',stateLabel(track.state))}</div><div class="grid compact-grid">${kpi('Creator token',num(track.created_token_count),'Kalıcı actor index')}${kpi('Baskın holder',num(track.dominant_holder_token_count),'Owner-resolved kalıcı hafıza')}${kpi('İşlem gördüğü token',num(track.traded_token_count),'Pump trade ledger')}${kpi('İlişkili aktör',num(track.related_actor_count),'Cross-token tekrar')}${kpi('VERIFIED kanıt',num(track.verified_evidence_count),'İmzalı zincir kanıtı')}${kpi('OBSERVED kanıt',num(track.observed_evidence_count),'Açık kapsamlı gözlem')}</div>${renderRuleVerdict(ruleVerdict)}${renderFunding(funding)}<div class="metadata section-gap"><div><label>Track ID</label><b class="mono">${esc(short(track.id,34))}</b></div><div><label>Durum</label><b>${esc(stateLabel(track.state))}</b></div><div><label>Son soruşturma</label><b>${dt(track.last_investigated_at)}</b></div><div><label>Canlı RPC</label><b>${esc(String(live.status||'stored_evidence_only').toUpperCase())}</b></div><div><label>Parsed transaction</label><b>${num(live.transactions_parsed)}</b></div><div><label>Yeni kanıt</label><b>${num(live.evidence_persisted)}</b></div></div><details class="owner-details section-gap" open><summary><span><b>Token operasyon yüzeyi</b><small>Creator/deployer, baskın holder ve Pump trader rolleri ayrı tutulur.</small></span><span>⌄</span></summary><div class="section-gap">${renderTokens(tokens)}</div></details><details class="owner-details section-gap" open><summary><span><b>Cross-token aktör korelasyonu</b><small>Aynı token kümesinde yeniden görünen owner-resolved cüzdanlar.</small></span><span>⌄</span></summary><div class="section-gap">${renderActors(actors)}</div></details><details class="owner-details section-gap" open><summary><span><b>Transaction kanıt günlüğü</b><small>İmza, slot, yön ve token-account owner çözümlemesi.</small></span><span>⌄</span></summary><div class="section-gap">${renderEvidence(evidence)}</div></details><div class="warning-box section-gap"><b>Kanıt politikası</b><br>Sayısal risk skoru üretilmez. Kurallar grade’i belirler; AI yalnız tetiklenen kuralları insan diline çevirebilir. INFERRED watch-only, UNVERIFIED karar dışıdır. Cüzdan ilişkisi gerçek kişi kimliği veya kötü niyet iddiası değildir.${arr(live.limitations).length?`<br><br>${arr(live.limitations).map(esc).join(' · ')}`:''}</div></div>`;
  }

  async function investigate(target,rootId){
    const root=rootFor(rootId);
    if(!root)throw new Error('Tarama alanı bulunamadı.');
    root.innerHTML='<div class="card loading">Koschei Defense Network creator, funding, holder, trade ve transaction kanıtlarını kurallarla ilişkilendiriyor…</div>';
    const controller=new AbortController();
    const timer=setTimeout(()=>controller.abort(),180000);
    try{
      const response=await fetch('/api/owner/defense/investigate',{method:'POST',credentials:'same-origin',signal:controller.signal,headers:{'Content-Type':'application/json'},body:JSON.stringify({target,network:'solana-mainnet',live_evidence:true})});
      let data={};
      try{data=await response.json();}catch{}
      if(!response.ok||data.ok===false)throw new Error(data.message||data.detail||data.error||`İstek başarısız (${response.status})`);
      renderDefense(root,data);
      loadDefenseQueue();
      return data;
    }catch(error){
      const message=error?.name==='AbortError'?'Actor investigation 180 saniyede tamamlanamadı.':(error?.message||'Actor investigation başarısız oldu.');
      root.innerHTML=`<div class="card error-state"><div><b>Actor investigation tamamlanamadı.</b><span>${esc(message)}</span></div></div>`;
      throw error;
	}finally{clearTimeout(timer);}
  }

  async function scan(target,rootId){
    try{return await originalScan(target,rootId)}catch(error){
      if(Number(error?.status)!==422)throw error;
      return investigate(target,rootId);
    }
  }

  function queueTable(items){
    if(!items.length)return'<div class="empty">Henüz kalıcı actor track oluşmadı. Sensör korelasyonu veri geldikçe kuyruğu otomatik doldurur.</div>';
    return`<div class="table-wrap"><table class="table"><thead><tr><th>Rule band / grade</th><th>Wallet / durum</th><th>Tetiklenen kurallar</th><th>Kanıt yüzeyi</th><th>Sonraki doğrulama</th><th>İşlem</th></tr></thead><tbody>${items.map(item=>{const track=obj(item.track),verdict=obj(item.rule_verdict),rules=arr(verdict.triggered_rules);return`<tr><td>${badge(item.verification_band,bandLabel(item.verification_band))}<div style="font-size:26px;font-weight:900;margin-top:7px">${esc(verdict.grade&&verdict.grade!=='-'?verdict.grade:'—')}</div><div class="muted small">${esc(verdict.ruleset_version||'')}</div></td><td><span class="mono">${esc(short(track.target_id,35))}</span><div class="section-gap">${badge(track.state,stateLabel(track.state))}${item.needs_live_evidence?' '+badge('observed','CANLI KANIT GEREKLİ'):''}</div></td><td>${rules.map(rule=>`<div><b>${esc(rule.rule_id)}</b> · ${esc(rule.evidence_status).toUpperCase()}${Number(rule.count||0)>1?` ×${num(rule.count)}`:''}</div>`).join('')||'<span class="muted">Grade-changing rule yok</span>'}<div class="muted small">${esc(item.band_reason||'')}</div></td><td>${num(track.created_token_count)} creator · ${num(track.dominant_holder_token_count)} baskın holder<div class="muted small">${num(track.related_actor_count)} ilişkili aktör · ${num(track.verified_evidence_count)} VERIFIED · ${num(track.observed_evidence_count)} OBSERVED</div></td><td><b>${esc(actionLabel(item.next_action))}</b><div class="muted small">Son gözlem ${dt(track.last_seen_at)}</div></td><td><button class="btn small" type="button" data-defense-investigate="${esc(track.target_id)}">Dossier aç</button></td></tr>`}).join('')}</tbody></table></div>`;
  }

  function renderDefenseQueue(payload){
    const panel=document.getElementById('ownerDefenseQueuePanel');
    if(!panel)return;
    const queue=obj(payload.queue),counts=obj(queue.counts),items=arr(queue.items),policy=obj(queue.policy);
    panel.innerHTML=`<div class="card-head"><div><span class="eyebrow">KOSCHEI DEFENSE NETWORK · RULE QUEUE</span><h2>Actor doğrulama sırası</h2><p class="muted">Ağırlıklı puan yok. Sıra açık rule band’leriyle belirlenir: HARD TRIGGER → COMPOUNDING → EVIDENCE PENDING → WATCH.</p></div><div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap"><span class="badge ok">${num(queue.total)} track</span><button class="btn small" type="button" data-defense-queue-refresh>Yenile</button></div></div><div class="grid compact-grid">${kpi('İlişkilendirildi',num(counts.correlated),'Cross-token tekrar')}${kpi('Doğrulandı',num(counts.verified),'Transaction kanıtı')}${kpi('Takipte',num(counts.tracked),'Tekrar gözlemi')}${kpi('Uyarı',num(counts.alerted),'Owner alert state')}</div><div class="section-gap">${queueTable(items)}</div><div class="warning-box section-gap"><b>Ruleset politikası</b><br>${esc(policy.ruleset_version||'—')} · Sayısal skor: KAPALI · INFERRED: WATCH ONLY · UNVERIFIED: HARİÇ. Son güncelleme: ${esc(dt(queue.generated_at))}</div>`;
    bindDefenseQueueActions();
  }

  function bindDefenseQueueActions(){
    document.querySelectorAll('[data-defense-queue-refresh]').forEach(button=>button.onclick=()=>loadDefenseQueue(true));
    document.querySelectorAll('[data-defense-investigate]').forEach(button=>button.onclick=async()=>{
      const wallet=button.dataset.defenseInvestigate;
      const input=document.getElementById('ownerRadarTarget');
      if(input)input.value=wallet;
      const result=document.getElementById('ownerRadarResult');
      result?.scrollIntoView({behavior:'smooth',block:'start'});
      button.disabled=true;
      try{await investigate(wallet,'ownerRadarResult')}finally{button.disabled=false}
    });
  }

  let queueRequest=0;
  async function loadDefenseQueue(force=false){
    const panel=document.getElementById('ownerDefenseQueuePanel');
    if(!panel)return;
    if(panel.dataset.loading==='true'&&!force)return;
    panel.dataset.loading='true';
    const request=++queueRequest;
    if(!panel.dataset.loaded)panel.innerHTML='<div class="card loading">Kalıcı actor track’leri ve kural band’leri yükleniyor…</div>';
    const controller=new AbortController();
    const timer=setTimeout(()=>controller.abort(),30000);
    try{
      const response=await fetch('/api/owner/defense/tracks?network=solana-mainnet&limit=50',{credentials:'same-origin',signal:controller.signal});
      let data={};
	  try{data=await response.json();}catch{}
      if(!response.ok||data.ok===false)throw new Error(data.message||data.detail||data.error||`İstek başarısız (${response.status})`);
      if(request!==queueRequest)return;
      panel.dataset.loaded='true';
      renderDefenseQueue(data);
    }catch(error){
      if(request!==queueRequest)return;
      const message=error?.name==='AbortError'?'Threat queue 30 saniyede yüklenemedi.':(error?.message||'Threat queue yüklenemedi.');
      panel.innerHTML=`<div class="card error-state"><div><b>Actor doğrulama kuyruğu yüklenemedi.</b><span>${esc(message)}</span></div><button class="btn small" type="button" data-defense-queue-refresh>Tekrar dene</button></div>`;
      bindDefenseQueueActions();
    }finally{
      clearTimeout(timer);
      if(request===queueRequest)panel.dataset.loading='false';
    }
  }

  function ensureDefenseQueuePanel(){
    const root=document.getElementById('arvisContent');
    const grid=root?.querySelector(':scope > .grid.compact-grid');
    if(!grid||document.getElementById('ownerDefenseQueuePanel'))return;
    const panel=document.createElement('article');
    panel.id='ownerDefenseQueuePanel';
    panel.className='card span-12';
    const anchor=grid.children[1]||null;
    grid.insertBefore(panel,anchor);
    loadDefenseQueue();
  }

  const arvisRoot=document.getElementById('arvisContent');
  if(arvisRoot){
    new MutationObserver(()=>ensureDefenseQueuePanel()).observe(arvisRoot,{childList:true});
    ensureDefenseQueuePanel();
  }

  window.OwnerRadarKit={...kit,scan,investigate,loadDefenseQueue,render:(root,data)=>String(data?.schema_version||'').startsWith('koschei-actor-defense-v')?renderDefense(root,data):originalRender(root,data),renderDefense};
})();
