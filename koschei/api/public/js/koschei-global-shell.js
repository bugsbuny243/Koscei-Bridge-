(function(){
  function ready(fn){if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',fn,{once:true});}else{fn();}}

  var translations={
    'Dashboard':'Panel','Radar':'Güvenlik Radarı','Token-2022':'Token-2022','Firewall':'İşlem Güvenliği','Watchlist':'İzleme Listesi','Webhooks':'Webhooklar','Integrate':'Entegrasyon','Plans':'Paketler',
    'Architecture':'Mimari','Developers':'Geliştiriciler','Integration Pilot':'Entegrasyon Pilotu','KOSCH Access':'KOSCH Erişimi','Token':'Token','Account':'Hesap','Reports':'Raporlar','Chain Health':'Zincir Sağlığı','Safe Check':'Güvenli Kontrol',
    'ARVIS Security Radar':'ARVIS Güvenlik Radarı','Complete evidence intelligence':'Eksiksiz kanıt istihbaratı','Özet değil. Tam risk dosyası.':'Özet değil. Tam güvenlik dosyası.',
    'Discovery':'Keşif','Distribution':'Dağılım','Structure':'Yapı','Evidence':'Kanıt','Pump + creator relation':'Pump ve creator bağlantısı','Yapısal floor':'Yapısal taban',
    'Warning / High Risk':'Uyarı / Yüksek Risk','Monitor':'İzleme','Complete ARVIS intelligence file':'Eksiksiz ARVIS istihbarat dosyası',
    'Free basic preflight':'Ücretsiz temel ön kontrol','Target':'Hedef','Recipient Shield':'Alıcı Adresi Kalkanı','Safe Check Çalıştır':'Güvenli Kontrolü Çalıştır',
    'Bu Radar değil':'Bu yalnız hızlı kontroldür','No evidence, no claim. Şüphe varsa önce dur, sonra doğrula.':'Kanıt yoksa kesin hüküm yok. Şüphe varsa önce dur, sonra doğrula.',
    'BLOCK':'ENGELLE','WARN':'UYARI','REVIEW':'İNCELE','ALLOW':'İZİN VER','Basic preflight risk':'Temel ön kontrol riski','ARVIS preflight tamamlandı.':'ARVIS ön kontrolü tamamlandı.',
    'WARNING':'UYARI','MONITOR':'İZLEME','NO DATA':'VERİ YOK','VERIFIED':'DOĞRULANDI','INSUFFICIENT EVIDENCE':'YETERSİZ KANIT','REVOKED':'KAPALI',
    'RISK / 100':'RİSK / 100','ARVIS VERDICT':'ARVIS KARARI','CREATOR / DEPLOYER RELATION':'CREATOR / DEPLOYER BAĞLANTISI','Source-reported creator/deployer wallet':'Kaynak tarafından bildirilen creator/deployer cüzdanı',
    'Observed source relation. This is not proof of wrongdoing or real-world identity.':'Gözlenen kaynak bağlantısıdır; kötü niyetin veya gerçek dünya kimliğinin kanıtı değildir.',
    'HOLDER CONCENTRATION':'HOLDER YOĞUNLUĞU','AUTHORITY STATUS':'YETKİ DURUMU','WARNING EXPLANATION':'UYARI AÇIKLAMASI','POSITIVE SIGNALS':'OLUMLU SİNYALLER',
    'ALL ARVIS MODULES':'TÜM ARVIS MODÜLLERİ','RELATION GRAPH':'İLİŞKİ GRAFİĞİ','TOP TOKEN ACCOUNTS':'EN BÜYÜK TOKEN HESAPLARI','COMPLETE EVIDENCE LOG':'EKSİKSİZ KANIT KAYDI','SOURCE & FINAL SIGNALS':'KAYNAK VE SON SİNYALLER',
    'Final verdict signals':'Son karar sinyalleri','Launch/source signals':'Launch ve kaynak sinyalleri','Creator / deployer':'Creator / deployer','unknown':'belirsiz','ARVIS module':'ARVIS modülü',
    'ARVIS command center':'ARVIS komuta merkezi','Evidence-backed only':'Yalnızca kanıta dayalı','User':'Kullanıcı',
    'ARVIS unified radar':'ARVIS birleşik radarı','One radar. Evidence first.':'Tek radar. Önce kanıt.',
    'Solana is the first live market. ARVIS returns a score only when verified on-chain or claim-surface evidence exists. Missing data never becomes a grade or signed report.':'İlk canlı pazar Solana’dır. ARVIS yalnız doğrulanmış zincir üstü veya bağlantı yüzeyi kanıtı varsa skor üretir. Eksik veri hiçbir zaman nota veya imzalı rapora dönüşmez.',
    'Live Radar':'Canlı Radar','Go security services':'Go güvenlik servisleri','Runtime engines':'Çalışan motorlar','Checking…':'Kontrol ediliyor…','Output rule':'Çıktı kuralı','Signed + evidence':'İmzalı ve kanıtlı',
    'Run ARVIS':'ARVIS’i çalıştır','Active Plan':'Aktif Erişim','Remaining Outputs':'Kalan Çıktı','Core Status':'Temel Durum','Pipeline':'İşlem hattı','Stream':'Akış','Runtime arms':'Çalışan kanıt kolları','Visible cards':'Görünen kartlar','Processed':'İşlenen','No evidence':'Kanıt yok','Failed':'Başarısız','Last event':'Son olay',
    'Reading entitlement.':'Erişim bilgisi okunuyor.','Failed evidence collection is not charged.':'Başarısız kanıt toplama işlemi ücrete tabi değildir.','Loading account access and ARVIS status…':'Hesap erişimi ve ARVIS durumu yükleniyor…',
    'View Plans':'KOSCH Erişimini Aç','Open Live Radar':'Canlı Radarı Aç','Explore Tools':'Araçları İncele','No active plan':'Aktif erişim yok','Choose a plan to unlock customer scans.':'Gelişmiş taramalar için KOSCH erişimini doğrulayın.','Entitlement verified.':'Erişim doğrulandı.','Get Outputs':'KOSCH Erişimini Aç',
    'Choose a plan to run ARVIS':'ARVIS’i çalıştırmak için KOSCH erişimini açın','The live production radar remains visible, while customer scans, reports, watchlists and alerts require an active package.':'Canlı üretim radarı görüntülenebilir; müşteri taramaları, raporlar, izleme listeleri ve alarmlar için KOSCH erişimi gerekir.',
    'No outputs remaining':'Kalan çıktı yok','Your package is active, but a new output allocation is required before another customer scan can run.':'Erişim aktif ancak yeni müşteri taraması için kapasite gerekir.','Enter a target. A verdict appears only after evidence verification.':'Bir hedef girin. Karar yalnız kanıt doğrulandıktan sonra görünür.',
    'Locked':'Kilitli','Live':'Canlı','Stale':'Güncelliğini yitirmiş','Waiting':'Bekleniyor','verified':'doğrulanmış','verified evidence':'doğrulanmış kanıt','ARVIS engine':'ARVIS motoru','Verified observation':'Doğrulanmış gözlem','Real data unavailable. No output was charged.':'Gerçek veri kullanılamıyor. Çıktı hakkı düşülmedi.','Signed ARVIS verdict':'İmzalı ARVIS kararı','Verified verdict':'Doğrulanmış karar','Vault':'Rapor Kasası','Enter a target.':'Bir hedef girin.','Collecting verified evidence…':'Doğrulanmış kanıt toplanıyor…','Analysis failed.':'Analiz başarısız.','Verified evidence unavailable.':'Doğrulanmış kanıt kullanılamıyor.','No output was charged.':'Çıktı hakkı düşülmedi.','ARVIS response unavailable.':'ARVIS yanıtı kullanılamıyor.'
  };

  function translateString(value){
    var text=String(value||'');
    var trimmed=text.trim();
    if(translations[trimmed]) return text.replace(trimmed,translations[trimmed]);
    if(/^Enter a Solana token, pool, wallet, program, transaction or claim URL$/i.test(trimmed)) return 'Solana token, havuz, cüzdan, program, işlem veya bağlantı girin';
    return text;
  }

  function translate(root){
    if(!root||root.nodeType!==1)return;
    var walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);
    var nodes=[];while(walker.nextNode())nodes.push(walker.currentNode);
    nodes.forEach(function(node){var p=node.parentElement;if(!p||/^(SCRIPT|STYLE|CODE|PRE)$/.test(p.tagName))return;var next=translateString(node.nodeValue);if(next!==node.nodeValue)node.nodeValue=next;});
    root.querySelectorAll('input[placeholder],textarea[placeholder]').forEach(function(el){el.placeholder=translateString(el.placeholder);});
    document.documentElement.lang='tr';
  }

  function esc(value){return String(value==null?'':value).replace(/[&<>"']/g,function(ch){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch];});}
  function clamp(value){return Math.max(0,Math.min(100,Math.round(Number(value)||0)));}
  function grade(risk){return risk>=85?'F':risk>=70?'E':risk>=50?'D':risk>=35?'C':risk>=20?'B':'A';}
  function action(risk){return risk>=85?'UZAK DUR':risk>=65?'YÜKSEK DİKKAT':risk>=35?'DİKKAT':'İZLE';}
  function riskClass(risk){return risk>=65?'bad':risk>=35?'warn':'good';}
  function base58Address(value){return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(String(value||'').trim());}

  function installLandingQuickCheck(current){
    if(current!=='/')return;
    var run=document.getElementById('run'),target=document.getElementById('target'),intent=document.getElementById('intent'),result=document.getElementById('result');
    if(!run||!target||!intent||!result)return;
    run.onclick=async function(){
      var value=target.value.trim();
      if(!value){result.className='result show';result.innerHTML='<div class="line">Önce kontrol edilecek bağlantı, token, adres veya imza metnini gir.</div>';return;}
      run.disabled=true;run.textContent='Kontrol ediliyor…';result.className='result show';result.innerHTML='<div class="line">ARVIS canlı kanıtları inceliyor…</div>';
      try{
        if(base58Address(value)){
          var tokenResponse=await fetch('/api/token/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mint:value,network:'solana-mainnet'})});
          var tokenData=await tokenResponse.json().catch(function(){return {};});
          if(tokenResponse.ok){
            var risk=clamp(100-clamp(tokenData.score));
            var findings=Array.isArray(tokenData.findings)?tokenData.findings.slice(0,3):[];
            if(!findings.length)findings=['Canlı Solana taraması tamamlandı; belirgin authority veya holder yoğunluğu bulgusu dönmedi.'];
            result.innerHTML='<div class="score '+riskClass(risk)+'">'+esc(grade(risk))+' · '+esc(risk)+'/100</div><b>'+esc(action(risk))+'</b><p class="sub" style="margin-top:6px">Canlı token taraması tamamlandı.</p>'+findings.map(function(item){return '<div class="line">'+esc(item)+'</div>';}).join('')+'<div class="actions" style="margin-top:12px"><a class="btn primary" href="/scan/'+encodeURIComponent(value)+'">Kanıtlı sonucu aç</a><a class="btn" href="/security-radar?target='+encodeURIComponent(value)+'">Derin tarama</a></div>';
            return;
          }
          if(tokenResponse.status>=500)throw new Error('live_token_unavailable');
        }
        var response=await fetch('/api/arvis/preflight',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:value,intent:intent.value,note:'landing_instant_safe_check'})});
        var data=await response.json().catch(function(){return {};});
        if(!response.ok)throw new Error(data.error||'preflight_failed');
        var score=clamp(data.score||data.risk_index);var level=String(data.risk_level||'belirsiz').toLowerCase();var decision=String(data.decision||data.policy||'review').toLowerCase();
        var decisionLabel=decision==='blocked'||decision==='block'?'ENGELLE':decision==='warn'?'UYARI':decision==='allow'?'İZİN VER':'İNCELE';
        var reasons=(Array.isArray(data.reasons)?data.reasons:[]).concat(Array.isArray(data.next_steps)?data.next_steps:[]).slice(0,5);
        result.innerHTML='<div class="score '+riskClass(score)+'">'+esc(score)+'</div><b>'+esc(decisionLabel)+' · '+esc(level==='medium'?'orta':level==='high'?'yüksek':level==='low'?'düşük':level)+'</b><p class="sub" style="margin-top:6px">'+esc(data.human_message||data.verdict||'ARVIS ön kontrolü tamamlandı.')+'</p>'+reasons.map(function(item){return '<div class="line">'+esc(item)+'</div>';}).join('')+'<div class="actions" style="margin-top:12px"><a class="btn primary" href="/safe-check">Ayrıntılı kontrol</a><a class="btn" href="/security-radar?target='+encodeURIComponent(value)+'">Derin tarama</a></div>';
      }catch(error){
        result.innerHTML='<div class="line">Canlı güvenlik kanıtı alınamadı. Güvenli hüküm üretilmedi; şüpheli işlemi yapma ve daha sonra tekrar dene.</div>';
      }finally{run.disabled=false;run.textContent='ARVIS ile kontrol et';}
    };
  }

  function loadInvestigationShare(current){
    if(current!=='/security-radar'||window.KoscheiInvestigationShare||document.querySelector('script[data-koschei-investigation-share]'))return;
    var script=document.createElement('script');
    script.src='/js/investigation-share.js?v=1';
    script.async=true;
    script.dataset.koscheiInvestigationShare='true';
    document.head.appendChild(script);
  }

  ready(function(){
    var links=[['/live','Canlı SOC'],['/cases','Vakalar'],['/scan','Token Tara'],['/transaction-shield','İşlem Kalkanı'],['/safe-check','Güvenli Kontrol'],['/security-radar','Güvenlik Radarı'],['/dashboard','Panel'],['/kosch','KOSCH']];
    var current=(location.pathname||'/').replace(/\.html$/,'').replace(/\/$/,'')||'/';
    var existing=document.querySelector('.top .nav, header.top nav.nav, nav.top .nav');
    var nav=existing||document.createElement('nav');
    nav.className=(existing?'nav ':'')+'koschei-global-nav';
    nav.setAttribute('aria-label','Ana menü');
    while(nav.firstChild)nav.removeChild(nav.firstChild);
    links.forEach(function(item){var a=document.createElement('a');a.href=item[0];a.textContent=item[1];if(current===item[0])a.setAttribute('aria-current','page');nav.appendChild(a);});
    if(!existing){var top=document.querySelector('header.top,.top');if(top){nav.className+=' detached';top.parentNode.insertBefore(nav,top.nextSibling);}}
    if(current==='/dashboard'&&!document.querySelector('.koschei-safety-strip')){var strip=document.createElement('section');strip.className='koschei-safety-strip';strip.innerHTML='<div><b>Satın almadan veya imzalamadan önce Koschei’ye sor.</b><span>Token mintini canlı tara ya da Solana işlemini gönderilmeden önce simüle et.</span></div><span><a href="/scan">Token Tara</a> <a href="/transaction-shield">İşlem Kalkanı</a></span>';var anchor=document.querySelector('.koschei-global-nav')||document.querySelector('header.top,.top');if(anchor&&anchor.parentNode){anchor.parentNode.insertBefore(strip,anchor.nextSibling);}}
    var bottom=document.querySelector('nav.bottom');if(bottom)bottom.remove();
    if(!document.querySelector('.koschei-footer')){var footer=document.createElement('footer');footer.className='koschei-footer';footer.innerHTML='<span>Koschei ARVIS · Solana güvenlik merkezi</span><span><a href="/live">Canlı SOC</a> · <a href="/cases">Vakalar</a> · <a href="/scan">Token Tara</a> · <a href="/transaction-shield">İşlem Kalkanı</a> · <a href="/safe-check">Güvenli Kontrol</a> · <a href="/kosch">KOSCH</a></span>';document.body.appendChild(footer);}
    if(current==='/safe-check')document.title='Güvenli Kontrol — Koschei ARVIS';
    if(current==='/security-radar')document.title='Koschei ARVIS — Tam Güvenlik Radarı';
    translate(document.body);
    installLandingQuickCheck(current);
    loadInvestigationShare(current);
    var observer=new MutationObserver(function(records){records.forEach(function(record){record.addedNodes.forEach(function(node){if(node.nodeType===1)translate(node);else if(node.nodeType===3&&node.parentElement){var next=translateString(node.nodeValue);if(next!==node.nodeValue)node.nodeValue=next;}});});});
    observer.observe(document.body,{childList:true,subtree:true,characterData:false});
  });
})();
