(()=>{if(typeof document!=="undefined"&&!document.querySelector('script[data-koschei-english-runtime]')){const script=document.createElement('script');script.src='/js/koschei-english-runtime.js?v=1';script.dataset.koscheiEnglishRuntime='1';document.head.appendChild(script);}})();
(function(){
  function ready(fn){if(document.readyState==='loading'){document.addEventListener('DOMContentLoaded',fn,{once:true});}else{fn();}}

  function installBoundedAPIFetch(){
    if(window.__koscheiBoundedAPIFetchInstalled)return;
    window.__koscheiBoundedAPIFetchInstalled=true;
    var nativeFetch=window.fetch.bind(window);
    function timeoutFor(path){
      if(path==='/health')return 10000;
      if(path.indexOf('/api/token/scan')===0||path.indexOf('/api/v1/radar/')===0||path.indexOf('/api/owner/')===0||path.indexOf('/api/jobs/')===0)return 45000;
      return 15000;
    }
    window.fetch=function(input,init){
      var raw=typeof input==='string'?input:(input&&input.url)||'';
      var url;
      try{url=new URL(raw,window.location.origin);}catch{return nativeFetch(input,init);}
      var bounded=url.origin===window.location.origin&&(url.pathname==='/health'||url.pathname.indexOf('/api/')===0);
      if(!bounded)return nativeFetch(input,init);
      var controller=new AbortController();
      var externalSignal=init&&init.signal;
      var timedOut=false;
      var onExternalAbort=function(){controller.abort(externalSignal&&externalSignal.reason);};
      if(externalSignal){
        if(externalSignal.aborted)onExternalAbort();
        else externalSignal.addEventListener('abort',onExternalAbort,{once:true});
      }
      var timeoutMs=timeoutFor(url.pathname);
      var timer=window.setTimeout(function(){timedOut=true;controller.abort('koschei_api_timeout');},timeoutMs);
      var requestInit=Object.assign({},init||{},{signal:controller.signal});
      return nativeFetch(input,requestInit).catch(function(error){
        if(timedOut){throw new Error('DEGRADED DEPENDENCY — The evidence service did not respond within '+Math.round(timeoutMs/1000)+' seconds. No current result was produced.');}
        throw error;
      }).finally(function(){
        window.clearTimeout(timer);
        if(externalSignal)externalSignal.removeEventListener('abort',onExternalAbort);
      });
    };
  }

  installBoundedAPIFetch();

  var translations={
    'Panel':'Dashboard','Güvenlik Radarı':'Security Radar','İşlem Güvenliği':'Transaction Security','İşlem Kalkanı':'Transaction Shield','İzleme Listesi':'Watchlist','Webhooklar':'Webhooks','Entegrasyon':'Integrate','Paketler':'Plans',
    'Mimari':'Architecture','Geliştiriciler':'Developers','Entegrasyon Pilotu':'Integration Pilot','KOSCH Erişimi':'KOSCH Access','Hesap':'Account','Raporlar':'Reports','Zincir Sağlığı':'Chain Health','Güvenli Kontrol':'Safe Check',
    'ARVIS Güvenlik Radarı':'ARVIS Security Radar','Eksiksiz kanıt istihbaratı':'Complete evidence intelligence','Özet değil. Tam güvenlik dosyası.':'Not a summary. The complete security file.',
    'Keşif':'Discovery','Dağılım':'Distribution','Yapı':'Structure','Kanıt':'Evidence','Pump ve creator bağlantısı':'Pump and creator relation','Yapısal taban':'Structural floor',
    'Uyarı / Yüksek Risk':'Warning / High Risk','İzleme':'Monitor','Eksiksiz ARVIS istihbarat dosyası':'Complete ARVIS intelligence file',
    'Ücretsiz temel ön kontrol':'Free basic preflight','Hedef':'Target','Alıcı Adresi Kalkanı':'Recipient Shield','Güvenli Kontrolü Çalıştır':'Run Safe Check',
    'Bu yalnız hızlı kontroldür':'This is a rapid preflight only','Kanıt yoksa kesin hüküm yok. Şüphe varsa önce dur, sonra doğrula.':'No evidence, no claim. If uncertain, stop first and verify next.',
    'ENGELLE':'BLOCK','UYARI':'WARNING','İNCELE':'REVIEW','İZİN VER':'ALLOW','Temel ön kontrol riski':'Basic preflight risk','ARVIS ön kontrolü tamamlandı.':'ARVIS preflight completed.',
    'İZLEME':'MONITOR','VERİ YOK':'NO DATA','DOĞRULANDI':'VERIFIED','YETERSİZ KANIT':'INSUFFICIENT EVIDENCE','KAPALI':'DISABLED',
    'RİSK / 100':'RISK / 100','ARVIS KARARI':'ARVIS VERDICT','CREATOR / DEPLOYER BAĞLANTISI':'CREATOR / DEPLOYER RELATION','Kaynak tarafından bildirilen creator/deployer cüzdanı':'Source-reported creator/deployer wallet',
    'Gözlenen kaynak bağlantısıdır; kötü niyetin veya gerçek dünya kimliğinin kanıtı değildir.':'Observed source relation. This is not proof of wrongdoing or real-world identity.',
    'HOLDER YOĞUNLUĞU':'HOLDER CONCENTRATION','YETKİ DURUMU':'AUTHORITY STATUS','UYARI AÇIKLAMASI':'WARNING EXPLANATION','OLUMLU SİNYALLER':'POSITIVE SIGNALS',
    'TÜM ARVIS MODÜLLERİ':'ALL ARVIS MODULES','İLİŞKİ GRAFİĞİ':'RELATION GRAPH','EN BÜYÜK TOKEN HESAPLARI':'TOP TOKEN ACCOUNTS','EKSİKSİZ KANIT KAYDI':'COMPLETE EVIDENCE LOG','KAYNAK VE SON SİNYALLER':'SOURCE & FINAL SIGNALS',
    'Son karar sinyalleri':'Final verdict signals','Launch ve kaynak sinyalleri':'Launch and source signals','belirsiz':'unknown','ARVIS modülü':'ARVIS module','ARVIS komuta merkezi':'ARVIS command center','Yalnızca kanıta dayalı':'Evidence-backed only','Kullanıcı':'User',
    'ARVIS birleşik radarı':'ARVIS unified radar','Tek radar. Önce kanıt.':'One radar. Evidence first.','Canlı Radar':'Live Radar','Go güvenlik servisleri':'Go security services','Çalışan motorlar':'Runtime engines','Kontrol ediliyor…':'Checking…',
    'Çıktı kuralı':'Output rule','İmzalı ve kanıtlı':'Signed + evidence','ARVIS’i çalıştır':'Run ARVIS','Aktif Erişim':'Active Access','Kalan Çıktı':'Remaining Outputs','Temel Durum':'Core Status','İşlem hattı':'Pipeline','Akış':'Stream',
    'Çalışan kanıt kolları':'Runtime evidence arms','Görünen kartlar':'Visible cards','İşlenen':'Processed','Kanıt yok':'No evidence','Başarısız':'Failed','Son olay':'Last event','Erişim bilgisi okunuyor.':'Reading access status.',
    'Başarısız kanıt toplama işlemi ücrete tabi değildir.':'Failed evidence collection does not consume capacity.','Hesap erişimi ve ARVIS durumu yükleniyor…':'Loading account access and ARVIS status…','KOSCH Erişimini Aç':'Open KOSCH Access',
    'Canlı Radarı Aç':'Open Live Radar','Araçları İncele':'Explore Tools','Aktif erişim yok':'No active access','Gelişmiş taramalar için KOSCH erişimini doğrulayın.':'Verify KOSCH access to unlock advanced investigations.','Erişim doğrulandı.':'Access verified.',
    'ARVIS’i çalıştırmak için KOSCH erişimini açın':'Open KOSCH access to run ARVIS','Canlı üretim radarı görüntülenebilir; müşteri taramaları, raporlar, izleme listeleri ve alarmlar için KOSCH erişimi gerekir.':'The live production radar remains visible; customer scans, reports, watchlists, and alerts require KOSCH access.',
    'Kalan çıktı yok':'No remaining capacity','Erişim aktif ancak yeni müşteri taraması için kapasite gerekir.':'Access is active, but another customer investigation requires available capacity.','Bir hedef girin. Karar yalnız kanıt doğrulandıktan sonra görünür.':'Enter a target. A verdict appears only after evidence verification.',
    'Kilitli':'Locked','Canlı':'Live','Güncelliğini yitirmiş':'Stale','Bekleniyor':'Waiting','doğrulanmış':'verified','doğrulanmış kanıt':'verified evidence','ARVIS motoru':'ARVIS engine','Doğrulanmış gözlem':'Verified observation',
    'Gerçek veri kullanılamıyor. Çıktı hakkı düşülmedi.':'Real data is unavailable. No capacity was consumed.','İmzalı ARVIS kararı':'Signed ARVIS verdict','Doğrulanmış karar':'Verified verdict','Rapor Kasası':'Report Vault',
    'Bir hedef girin.':'Enter a target.','Doğrulanmış kanıt toplanıyor…':'Collecting verified evidence…','Analiz başarısız.':'Analysis failed.','Doğrulanmış kanıt kullanılamıyor.':'Verified evidence is unavailable.','Çıktı hakkı düşülmedi.':'No capacity was consumed.','ARVIS yanıtı kullanılamıyor.':'ARVIS response is unavailable.',
    'Canlı SOC':'Live SOC','Vakalar':'Cases','Token Tara':'Token Scan','Ana menü':'Main navigation','Satın almadan veya imzalamadan önce Koschei’ye sor.':'Ask Koschei before buying or signing.','Token mintini canlı tara ya da Solana işlemini gönderilmeden önce simüle et.':'Scan the token mint live or simulate a Solana transaction before sending it.',
    'Koschei ARVIS · Solana güvenlik merkezi':'Koschei ARVIS · Solana security center'
  };

  function translateString(value){
    var source=String(value||'');
    var trimmed=source.trim();
    if(translations[trimmed])return source.replace(trimmed,translations[trimmed]);
    if(/^Solana token, havuz, cüzdan, program, işlem veya bağlantı girin$/i.test(trimmed))return 'Enter a Solana token, pool, wallet, program, transaction, or claim URL';
    return source;
  }

  function translate(root){
    if(!root||root.nodeType!==1)return;
    var walker=document.createTreeWalker(root,NodeFilter.SHOW_TEXT);
    var nodes=[];while(walker.nextNode())nodes.push(walker.currentNode);
    nodes.forEach(function(node){var parent=node.parentElement;if(!parent||/^(SCRIPT|STYLE|CODE|PRE)$/.test(parent.tagName))return;var next=translateString(node.nodeValue);if(next!==node.nodeValue)node.nodeValue=next;});
    root.querySelectorAll('input[placeholder],textarea[placeholder]').forEach(function(element){element.placeholder=translateString(element.placeholder);});
    document.documentElement.lang='en';
  }

  function esc(value){return String(value==null?'':value).replace(/[&<>"']/g,function(char){return {'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot',"'":'&#39;'}[char];});}
  function clamp(value){return Math.max(0,Math.min(100,Math.round(Number(value)||0)));}
  function grade(risk){return risk>=85?'F':risk>=70?'E':risk>=50?'D':risk>=35?'C':risk>=20?'B':'A';}
  function action(risk){return risk>=85?'AVOID':risk>=65?'HIGH CAUTION':risk>=35?'CAUTION':'MONITOR';}
  function riskClass(risk){return risk>=65?'bad':risk>=35?'warn':'good';}
  function base58Address(value){return /^[1-9A-HJ-NP-Za-km-z]{32,44}$/.test(String(value||'').trim());}

  function installLandingQuickCheck(current){
    if(current!=='/'||document.querySelector('.hero-copy'))return;
    var run=document.getElementById('run'),target=document.getElementById('target'),intent=document.getElementById('intent'),result=document.getElementById('result');
    if(!run||!target||!intent||!result)return;
    run.onclick=async function(){
      var value=target.value.trim();
      if(!value){result.className='result show';result.innerHTML='<div class="line">Enter a URL, token, address, or signature request first.</div>';return;}
      run.disabled=true;run.textContent='Checking…';result.className='result show';result.innerHTML='<div class="line">ARVIS is collecting live evidence…</div>';
      try{
        if(base58Address(value)){
          var tokenResponse=await fetch('/api/token/scan',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({mint:value,network:'solana-mainnet'})});
          var tokenData=await tokenResponse.json().catch(function(){return {};});
          if(tokenResponse.ok){
            var risk=clamp(100-clamp(tokenData.score));
            var findings=Array.isArray(tokenData.findings)?tokenData.findings.slice(0,3):[];
            if(!findings.length)findings=['The live Solana scan completed without an additional authority or holder-concentration finding.'];
            result.innerHTML='<div class="score '+riskClass(risk)+'">'+esc(grade(risk))+' · '+esc(risk)+'/100</div><b>'+esc(action(risk))+'</b><p class="sub" style="margin-top:6px">Live token scan completed.</p>'+findings.map(function(item){return '<div class="line">'+esc(item)+'</div>';}).join('')+'<div class="actions" style="margin-top:12px"><a class="btn primary" href="/scan/'+encodeURIComponent(value)+'">Open evidence result</a><a class="btn" href="/security-radar?target='+encodeURIComponent(value)+'">Run deep scan</a></div>';
            return;
          }
          if(tokenResponse.status>=500)throw new Error('live_token_unavailable');
        }
        var response=await fetch('/api/arvis/preflight',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({target:value,intent:intent.value,note:'landing_instant_safe_check'})});
        var data=await response.json().catch(function(){return {};});
        if(!response.ok)throw new Error(data.error||'preflight_failed');
        var score=clamp(data.score||data.risk_index),level=String(data.risk_level||'unknown').toLowerCase(),decision=String(data.decision||data.policy||'review').toLowerCase();
        var decisionLabel=decision==='blocked'||decision==='block'?'BLOCK':decision==='warn'?'WARNING':decision==='allow'?'ALLOW':'REVIEW';
        var reasons=(Array.isArray(data.reasons)?data.reasons:[]).concat(Array.isArray(data.next_steps)?data.next_steps:[]).slice(0,5);
        result.innerHTML='<div class="score '+riskClass(score)+'">'+esc(score)+'</div><b>'+esc(decisionLabel)+' · '+esc(level)+'</b><p class="sub" style="margin-top:6px">'+esc(data.human_message||data.verdict||'ARVIS preflight completed.')+'</p>'+reasons.map(function(item){return '<div class="line">'+esc(item)+'</div>';}).join('')+'<div class="actions" style="margin-top:12px"><a class="btn primary" href="/safe-check">Open Safe Check</a><a class="btn" href="/security-radar?target='+encodeURIComponent(value)+'">Run deep scan</a></div>';
      }catch(error){
        result.innerHTML='<div class="line">DEGRADED DEPENDENCY — Live security evidence is unavailable. No safe verdict was produced; do not proceed with a suspicious action and retry later.</div>';
      }finally{run.disabled=false;run.textContent='Check with ARVIS';}
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
    var links=[['/live','Live SOC'],['/cases','Cases'],['/scan','Token Scan'],['/transaction-shield','Transaction Shield'],['/safe-check','Safe Check'],['/security-radar','Security Radar'],['/dashboard','Workspace'],['/kosch','KOSCH']];
    var current=(location.pathname||'/').replace(/\.html$/,'').replace(/\/$/,'')||'/';
    var existing=document.querySelector('.top .nav, header.top nav.nav, nav.top .nav');
    var nav=existing||document.createElement('nav');
    nav.className=(existing?'nav ':'')+'koschei-global-nav';
    nav.setAttribute('aria-label','Main navigation');
    while(nav.firstChild)nav.removeChild(nav.firstChild);
    links.forEach(function(item){var anchor=document.createElement('a');anchor.href=item[0];anchor.textContent=item[1];if(current===item[0])anchor.setAttribute('aria-current','page');nav.appendChild(anchor);});
    if(!existing){var top=document.querySelector('header.top,.top');if(top){nav.className+=' detached';top.parentNode.insertBefore(nav,top.nextSibling);}}
    if(current==='/dashboard'&&!document.querySelector('.koschei-safety-strip')){var strip=document.createElement('section');strip.className='koschei-safety-strip';strip.innerHTML='<div><b>Ask Koschei before buying or signing.</b><span>Scan the token mint live or simulate a Solana transaction before sending it.</span></div><span><a href="/scan">Token Scan</a> <a href="/transaction-shield">Transaction Shield</a></span>';var stripAnchor=document.querySelector('.koschei-global-nav')||document.querySelector('header.top,.top');if(stripAnchor&&stripAnchor.parentNode){stripAnchor.parentNode.insertBefore(strip,stripAnchor.nextSibling);}}
    var bottom=document.querySelector('nav.bottom');if(bottom)bottom.remove();
    if(!document.querySelector('.koschei-footer')){var footer=document.createElement('footer');footer.className='koschei-footer';footer.innerHTML='<span>Koschei ARVIS · Solana security center</span><span><a href="/live">Live SOC</a> · <a href="/cases">Cases</a> · <a href="/scan">Token Scan</a> · <a href="/transaction-shield">Transaction Shield</a> · <a href="/safe-check">Safe Check</a> · <a href="/kosch">KOSCH</a></span>';document.body.appendChild(footer);}
    if(current==='/safe-check')document.title='Safe Check — Koschei ARVIS';
    if(current==='/security-radar')document.title='Koschei ARVIS — Full Security Radar';
    translate(document.body);
    installLandingQuickCheck(current);
    loadInvestigationShare(current);
    var observer=new MutationObserver(function(records){records.forEach(function(record){record.addedNodes.forEach(function(node){if(node.nodeType===1)translate(node);else if(node.nodeType===3&&node.parentElement){var next=translateString(node.nodeValue);if(next!==node.nodeValue)node.nodeValue=next;}});});});
    observer.observe(document.body,{childList:true,subtree:true,characterData:false});
  });
})();
