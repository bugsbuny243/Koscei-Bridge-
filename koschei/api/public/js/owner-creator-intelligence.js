(()=>{
  'use strict';

  const kit=window.OwnerRadarKit;
  if(!kit||window.__ownerCreatorIntelligenceInstalled)return;
  window.__ownerCreatorIntelligenceInstalled=true;

  const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  const arr=value=>Array.isArray(value)?value:[];
  const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
  const num=(value,digits=0)=>{const n=Number(value);return Number.isFinite(n)?new Intl.NumberFormat('tr-TR',{maximumFractionDigits:digits}).format(n):'—'};
  const short=(value,length=42)=>{const valueText=String(value||'');return valueText.length>length?`${valueText.slice(0,length-11)}…${valueText.slice(-8)}`:valueText||'—'};
  const text=(...values)=>values.map(value=>String(value??'').trim()).find(Boolean)||'';
  const rootFor=value=>typeof value==='string'?document.getElementById(value):value;
  const statusClass=value=>{const status=String(value||'').toLowerCase();if(status.includes('fail')||status.includes('error')||status.includes('unavailable'))return'bad';if(status.includes('verified')||status.includes('complete')||status.includes('persisted')||status.includes('resolved'))return'ok';return'warn'};
  const badge=value=>`<span class="badge ${statusClass(value)}">${esc(String(value||'unknown').replaceAll('_',' ').toUpperCase())}</span>`;
  const metric=(label,value,foot='')=>`<div><label>${esc(label)}</label><b>${esc(value)}</b>${foot?`<small>${esc(foot)}</small>`:''}</div>`;

  function uniqueCandidates(portfolio){
    const verified=arr(portfolio.verified_candidates).map(item=>({...obj(item),verification_status:'verified'}));
    const observed=arr(obj(portfolio.discovery).candidates);
    const seen=new Set();
    return [...verified,...observed].filter(item=>{
      const key=`${item.mint||''}|${item.signature||''}`;
      if(!item.mint||seen.has(key))return false;
      seen.add(key);
      return true;
    });
  }

  function candidateRows(portfolio){
    const rows=uniqueCandidates(portfolio);
    if(!rows.length)return'<div class="empty">Creator tarafından oluşturulduğu keşfedilen mint bulunmadı veya Helius/RPC kanıtı alınamadı.</div>';
    return `<div class="table-wrap"><table class="table"><thead><tr><th>Mint</th><th>Program / instruction</th><th>İmza</th><th>Slot</th><th>Doğrulama</th></tr></thead><tbody>${rows.slice(0,50).map(row=>`<tr><td class="mono"><b>${esc(short(row.mint,36))}</b></td><td><b>${esc(short(row.program,28))}</b><div class="muted small">${esc(row.instruction_type||'create')}</div></td><td class="mono">${esc(short(row.signature,30))}</td><td>${num(row.slot)}</td><td>${badge(row.verification_status||'observed')}</td></tr>`).join('')}</tbody></table></div>`;
  }

  function recipientRows(report){
    const recipients=arr(report.recipients);
    if(!recipients.length)return'<div class="empty">Creator ATA geçmişinde ilk recipient transferi doğrulanmadı.</div>';
    return `<div class="table-wrap"><table class="table"><thead><tr><th># / recipient</th><th>İlk miktar</th><th>Güncel bakiye</th><th>Top-holder bağı</th><th>Kanıt</th></tr></thead><tbody>${recipients.slice(0,20).map(row=>`<tr><td><b>#${num(row.sequence)}</b><div class="mono">${esc(short(row.wallet,34))}</div><div class="muted small">${esc(String(row.fate||'unknown').replaceAll('_',' '))}</div></td><td><b>${num(row.amount,6)}</b></td><td><b>${num(row.current_balance,6)}</b><div class="muted small">${esc(String(row.current_balance_status||'unknown').replaceAll('_',' '))}</div></td><td>${row.matches_top_holder?`<span class="badge bad">TOP #${num(row.top_holder_rank)}</span><div class="muted small">%${num(row.top_holder_percentage,4)}</div>`:'<span class="muted">Eşleşme yok</span>'}</td><td class="mono">${esc(short(row.signature,28))}<div class="muted small">slot ${num(row.slot)}</div></td></tr>`).join('')}</tbody></table></div>`;
  }

  function relationRows(dossier){
    const actors=arr(dossier.related_actors);
    if(!actors.length)return'<div class="empty">Kalıcı dossier içinde önemli karşı aktör ilişkisi yok.</div>';
    return `<div class="table-wrap"><table class="table"><thead><tr><th>Aktör</th><th>İlişki</th><th>Tekrar</th><th>Kanıt durumu</th></tr></thead><tbody>${actors.slice(0,30).map(row=>`<tr><td class="mono">${esc(short(text(row.wallet,row.actor_wallet,row.counterpart_id,row.address),34))}</td><td>${esc(text(row.relation,row.role,row.kind,'unknown'))}</td><td>${num(row.occurrence_count||row.count||1)}</td><td>${badge(text(row.verification_status,row.status,'observed'))}</td></tr>`).join('')}</tbody></table></div>`;
  }

  function fundingPanel(funding){
    funding=obj(funding);
    const wallet=text(funding.source_wallet,funding.funder_wallet,funding.funding_wallet,funding.origin_wallet,funding.counterpart_wallet);
    const signature=text(funding.signature,funding.transaction_signature);
    const amount=funding.amount_sol??funding.amount??funding.lamports;
    return `<div class="metadata section-gap">${metric('Durum',text(funding.status,'not observed'))}${metric('Doğrulama',text(funding.verification_status,'unverified'))}${metric('İlk fonlayıcı',short(wallet,34))}${metric('Miktar',amount==null?'—':String(amount))}${metric('İmza',short(signature,30))}${metric('İz durumu',text(funding.trail_status,'not investigated'))}</div>`;
  }

  function appendCreatorIntelligence(root,payload){
    root=rootFor(root);
    if(!root)return;
    root.querySelector('[data-canonical-creator-intelligence]')?.remove();

    payload=obj(payload);
    const actor=obj(payload.actor_investigation);
    const intelligence=obj(payload.creator_intelligence);
    const distribution=obj(payload.creator_distribution);
    const source=obj(payload.source_context);
    const dossier=obj(intelligence.dossier||actor.dossier);
    const external=obj(intelligence.external_discovery||actor.external_discovery);
    const discovery=obj(external.discovery);
    const portfolio=obj(external.created_mint_portfolio);
    const funding=obj(intelligence.funding_origin||actor.funding_origin);
    const relation=obj(intelligence.current_creator_relation||actor.current_creator_relation);
    const distributionContainer=Object.keys(distribution).length?distribution:obj(actor.current_token_distribution);
    const distributionReport=obj(distributionContainer.report);
    const creator=text(intelligence.creator_wallet,actor.wallet,dossier.wallet,source.creator_wallet);
    const actorLimitations=[...arr(intelligence.limitations),...arr(obj(actor.integration_run).limitations),...arr(external.limitations)];
    const distributionLimitations=[...arr(distributionContainer.limitations),...arr(distributionReport.limitations)];

    const panel=document.createElement('section');
    panel.className='card section-gap';
    panel.dataset.canonicalCreatorIntelligence='1';
    panel.innerHTML=`
      <div class="card-head"><div><span class="eyebrow">KOSCHEI CREATOR / ACTOR INTELLIGENCE</span><h2>Creator'ın zincir üstü dosyası</h2><p class="muted">Bu bölüm holder/cluster özetinin tekrarı değildir. Creator wallet, oluşturulan mintler, funding, ilişkili aktörler ve ilk dağıtım kanıtını gösterir.</p></div>${badge(text(intelligence.status,obj(actor.integration_run).status,'unknown'))}</div>
      <div class="metadata section-gap">
        ${metric('Creator wallet',short(creator,42))}
        ${metric('Dossier token',num(arr(dossier.tokens).length))}
        ${metric('İlişkili aktör',num(arr(dossier.related_actors).length))}
        ${metric('Actor evidence',num(arr(dossier.evidence).length))}
        ${metric('Store',text(intelligence.store_status,actor.store_status,'unknown'))}
        ${metric('Current mint relation',text(relation.status,relation.persistence,'unknown'))}
      </div>

      <details class="owner-details section-gap" open><summary><span><b>Creator mint portföyü</b><small>Helius enhanced transactions → Solana RPC signer ve create-instruction doğrulaması.</small></span><span>⌄</span></summary>
        <div class="metadata section-gap">
          ${metric('Portföy durumu',text(portfolio.status,'not requested'))}
          ${metric('Sayfa',num(obj(portfolio.discovery).pages_fetched))}
          ${metric('İşlem görüldü',num(obj(portfolio.discovery).transactions_seen))}
          ${metric('Aday',num(arr(obj(portfolio.discovery).candidates).length))}
          ${metric('Doğrulanan',num(portfolio.candidates_verified))}
          ${metric('Doğrulama hatası',num(portfolio.verification_failures))}
        </div>
        <div class="section-gap">${candidateRows(portfolio)}</div>
      </details>

      <details class="owner-details section-gap" open><summary><span><b>Funding origin ve dış attribution</b><small>Funding zincir üstü Solana RPC ile doğrulanır; harici servis etiketi kimlik veya kötü niyet kanıtı değildir.</small></span><span>⌄</span></summary>
        ${fundingPanel(funding)}
        <div class="metadata section-gap">
          ${metric('Dış keşif modu',text(discovery.status,'rpc only'))}
          ${metric('Funding kaynağı','Solana RPC')}
          ${metric('Creator mint kaynağı',text(obj(portfolio.discovery).provider,'helius'))}
          ${metric('Kalıcı dış kanıt',num(external.evidence_persisted))}
        </div>
      </details>

      <details class="owner-details section-gap" open><summary><span><b>Creator → mevcut mint → ilk recipient dağıtımı</b><small>Creator ATA geçmişi ve aynı-mint recipient bakiyesi; recipient-wide kör tarama yapılmaz.</small></span><span>⌄</span></summary>
        <div class="metadata section-gap">
          ${metric('Durum',text(distributionContainer.status,distributionReport.status,'not requested'))}
          ${metric('Scope',text(distributionReport.distribution_scope,'unknown'))}
          ${metric('Kaynak ATA',num(arr(distributionReport.source_token_accounts).length))}
          ${metric('İmza / tx',`${num(distributionReport.signatures_scanned)} / ${num(distributionReport.transactions_parsed)}`)}
          ${metric('Recipient',num(arr(distributionReport.recipients).length))}
          ${metric('Kalıcı kanıt',`${num(distributionContainer.evidence_persisted)} / ${num(distributionContainer.evidence_produced)}`)}
        </div>
        <div class="section-gap">${recipientRows(distributionReport)}</div>
      </details>

      <details class="owner-details section-gap"><summary><span><b>Cross-token ilişkili aktörler</b><small>Kalıcı actor dossier içindeki tekrar eden counterpart kayıtları.</small></span><span>⌄</span></summary><div class="section-gap">${relationRows(dossier)}</div></details>
      ${actorLimitations.length?`<div class="warning-box section-gap"><b>Actor soruşturması sınırları</b><br>${actorLimitations.map(esc).join(' · ')}</div>`:''}
      ${distributionLimitations.length?`<div class="warning-box section-gap"><b>Dağıtım sınırları</b><br>${distributionLimitations.map(esc).join(' · ')}</div>`:''}`;
    root.appendChild(panel);
  }

  const baseRender=typeof kit.render==='function'?kit.render.bind(kit):null;
  const baseUnified=typeof kit.renderUnified==='function'?kit.renderUnified.bind(kit):null;
  function render(root,payload){if(baseRender)baseRender(root,payload);appendCreatorIntelligence(root,payload);}
  function renderUnified(root,payload){if(baseUnified)baseUnified(root,payload);else if(baseRender)baseRender(root,payload);appendCreatorIntelligence(root,payload);}

  window.OwnerRadarKit={...kit,render,renderUnified,renderCreatorIntelligence:appendCreatorIntelligence};
})();
