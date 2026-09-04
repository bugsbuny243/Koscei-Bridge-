(()=>{
  'use strict';
  const kit=window.OwnerRadarKit;
  if(!kit||window.__ownerCourtUIInstalled)return;
  window.__ownerCourtUIInstalled=true;
  const esc=value=>String(value??'').replace(/[&<>"']/g,char=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[char]));
  const arr=value=>Array.isArray(value)?value:[];
  const obj=value=>value&&typeof value==='object'&&!Array.isArray(value)?value:{};
  const short=(value,length=56)=>{const text=String(value||'');return text.length>length?`${text.slice(0,length-12)}…${text.slice(-9)}`:text||'—'};
  const rootFor=value=>typeof value==='string'?document.getElementById(value):value;
  const sleep=ms=>new Promise(resolve=>setTimeout(resolve,ms));
  const directScan=typeof kit.scan==='function'?kit.scan:null;
  const statusLabel=value=>({ready:'BAĞIMSIZ İNCELEME TAMAMLANDI',partial:'KISMİ İNCELEME',error:'İNCELEME HATASI',disabled:'DERİN İNCELEME KAPALI',skipped:'UYGULANMADI',budget_exhausted:'GÜNLÜK LİMİT DOLDU'}[String(value||'').toLowerCase()]||String(value||'BİLİNMİYOR').toUpperCase());
  const stanceLabel=value=>({elevated:'YÜKSELTİLMİŞ İNCELEME',neutral:'NÖTR ANALİZ',insufficient:'KANIT YETERSİZ'}[String(value||'').toLowerCase()]||String(value||'KANIT YETERSİZ').toUpperCase());
  const tone=value=>{const text=String(value||'').toLowerCase();if(text==='ready'||text==='neutral')return'ok';if(text==='error'||text==='elevated')return'bad';return'warn'};
  const badge=(value,label)=>`<span class="badge ${tone(value)}">${esc(label||statusLabel(value))}</span>`;

  function evidenceChips(values){
    return arr(values).length?`<div class="court-evidence">${arr(values).map(value=>`<span>${esc(short(value,48))}</span>`).join('')}</div>`:'';
  }

  function limitations(values){
    return arr(values).length?`<div class="court-limitations"><b>Sınırlamalar</b><br>${arr(values).map(esc).join(' · ')}</div>`:'';
  }

  function renderOpinion(opinion,index){
    opinion=obj(opinion);
    const title=index===0?'Ana Kanıt Analizi':'Bağımsız Kanıt Kontrolü';
    return`<article class="court-opinion"><header><div><h3>${esc(title)}</h3><span class="court-model">${esc(opinion.provider||'provider')} · ${esc(opinion.model||'model')}</span></div>${badge(opinion.stance,stanceLabel(opinion.stance))}</header><p>${esc(opinion.text||'Analiz üretilemedi.')}</p>${evidenceChips(opinion.evidence_ids)}${limitations(opinion.limitations)}</article>`;
  }

  function renderPanel(panel,title,senior=false){
    panel=obj(panel);
    if(!Object.keys(panel).length)return'';
    const members=arr(panel.models).join(' · ');
    return`<article class="court-panel-card${senior?' senior':''}"><header><div><h3>${esc(title)}</h3><span class="court-model">${esc(members||'model bilgisi yok')}</span></div>${badge(panel.stance,stanceLabel(panel.stance))}</header><p>${esc(panel.text||'Bağımsız analiz üretilemedi.')}</p>${limitations(panel.limitations)}</article>`;
  }

  function renderCourt(report){
    report=obj(report);
    if(!Object.keys(report).length)return'';
    const prosecutors=arr(report.prosecutors),status=String(report.status||'unknown').toLowerCase();
    const statusClass=status==='ready'?'court-status-ready':status==='partial'?'court-status-partial':status==='error'?'court-status-error':'';
    const hasResult=prosecutors.length||Object.keys(obj(report.panel)).length||Object.keys(obj(report.senior)).length;
    return`<article class="card court-docket" id="arvis-court-docket"><div class="court-head"><div><span class="eyebrow">ARVIS INDEPENDENT REVIEW · READ-ONLY ANALYSIS RECORD</span><h2>Bağımsız model analizleri</h2><p class="muted">Modeller yalnız imzalı kanıt paketini yorumlar. Deterministik verdict, grade ve signature değiştirilemez.</p><div class="court-case-id">${esc(report.case_id||'analysis id üretilemedi')}</div></div><div class="${statusClass}">${badge(status,statusLabel(status))}</div></div><div class="court-authority"><b>Değişmez kaynak:</b> ${esc(report.authority||'İmzalı deterministik verdict nihai teknik kayıttır.')}</div>${hasResult?`<div class="court-stage-grid">${prosecutors.map(renderOpinion).join('')}${renderPanel(report.panel,'Teknik Tutarlılık Kontrolü')}${renderPanel(report.senior,'Kıdemli Çoklu-Model Sentezi',true)}</div>`:`<div class="court-empty section-gap">Bağımsız inceleme sonucu üretilemedi veya bu tarama için derin inceleme çalıştırılmadı.</div>`}${limitations(report.errors)}</article>`;
  }

  function appendCourt(root,payload){
    root=rootFor(root);
    if(!root)return;
    root.querySelector('#arvis-court-docket')?.remove();
    const html=renderCourt(payload?.court);
    if(html)root.insertAdjacentHTML('beforeend',html);
  }

  const baseRender=kit.renderUnified;
  function renderUnified(root,payload){
    if(typeof baseRender==='function')baseRender(root,payload);
    appendCourt(root,payload);
  }

  function renderJobProgress(root,job){
    const status=String(job.status||'queued').toLowerCase();
    const progress=Math.max(0,Math.min(100,Number(job.progress||0)));
    const label=status==='queued'?'Kuyrukta':status==='running'?'Soruşturuluyor':status==='completed'?'Tamamlandı':status==='failed'?'Başarısız':status;
    root.innerHTML=`<div class="card loading"><b>Kalıcı Koschei soruşturması: ${esc(label)}</b><br><span>İlerleme: ${esc(progress)}% · Deneme: ${esc(job.attempts||0)}</span><br><span>Bu iş tarayıcı bağlantısından bağımsız çalışır. Mint → creator → oluşturulan tokenlar → funding → recipient → holder → LP kanıt zinciri tamamlanıyor.</span></div>`;
  }

  async function pollCanonicalJob(pollUrl,root){
    for(;;){
      const response=await fetch(pollUrl,{method:'GET',credentials:'same-origin',cache:'no-store'});
      let data={};
      try{data=await response.json()}catch{}
      if(!response.ok||data.ok===false)throw new Error(data.message||data.detail||data.error||`Job sorgusu başarısız (${response.status})`);
      const job=obj(data.job);
      renderJobProgress(root,job);
      const status=String(job.status||'').toLowerCase();
      if(status==='completed'){
        const result=obj(job.result);
        if(!Object.keys(result).length)throw new Error('Soruşturma tamamlandı ancak canonical sonuç paketi boş döndü.');
        renderUnified(root,result);
        return result;
      }
      if(status==='failed')throw new Error(job.error_message||job.error_code||'Kalıcı soruşturma işi başarısız oldu.');
      await sleep(status==='queued'?1800:2500);
    }
  }

  async function scan(target,rootId){
    const root=rootFor(rootId);
    if(!root)throw new Error('Radar sonuç alanı bulunamadı.');
    root.innerHTML='<div class="card loading">Kalıcı canonical soruşturma işi oluşturuluyor…</div>';
    try{
      const response=await fetch('/api/owner/radar/jobs',{method:'POST',credentials:'same-origin',headers:{'Content-Type':'application/json'},body:JSON.stringify({target,network:'solana-mainnet',max_depth:1})});
      let data={};
      try{data=await response.json()}catch{}
      if(!response.ok||data.ok===false){
        // Canonical jobs need the retired application database and worker. A
        // stateless deployment must still run the live, synchronous scan.
        if(directScan&&[404,405,501,503].includes(response.status)){
          root.innerHTML='<div class="card loading">Kalıcı iş altyapısı kapalı; canlı ARVIS taraması başlatılıyor…</div>';
          return await directScan(target,root);
        }
        throw new Error(data.message||data.detail||data.error||`İş oluşturulamadı (${response.status})`);
      }
      const pollUrl=String(data.poll_url||'');
      if(!pollUrl&&directScan){
        root.innerHTML='<div class="card loading">Kalıcı iş yanıtı eksik; canlı ARVIS taraması başlatılıyor…</div>';
        return await directScan(target,root);
      }
      if(!pollUrl)throw new Error('Canonical job poll adresi üretilmedi.');
      renderJobProgress(root,obj(data.job));
      return await pollCanonicalJob(pollUrl,root);
    }catch(error){
      const message=error?.message||'Kalıcı soruşturma başlatılamadı.';
      root.innerHTML=`<div class="card error-state"><div><b>Geniş araştırma raporu tamamlanamadı.</b><span>${esc(message)}</span></div></div>`;
      throw error;
    }
  }

  window.OwnerRadarKit={...kit,scan,renderUnified,renderCourt};
})();
