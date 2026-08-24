(()=>{
  'use strict';
  if(window.__koscheiProductV2)return;
  window.__koscheiProductV2=true;
  const ready=fn=>document.readyState==='loading'?document.addEventListener('DOMContentLoaded',fn,{once:true}):fn();
  const HEALTH_TIMEOUT_MS=10000;

  function installSurfaceStyles(){
    if(document.querySelector('link[data-koschei-customer-surface-v3]'))return;
    const link=document.createElement('link');
    link.rel='stylesheet';
    link.href='/css/customer-surface-v3.css?v=1';
    link.dataset.koscheiCustomerSurfaceV3='1';
    document.head.appendChild(link);
  }

  function cleanPath(value){return (value||'/').replace(/\.html$/,'').replace(/\/$/,'')||'/';}
  function navActive(href,current){
    const url=new URL(href,location.origin),path=cleanPath(url.pathname);
    if(href==='/scan')return current==='/scan'||current.startsWith('/scan/');
    if(href==='/reports')return current==='/reports'||current==='/cases';
    if(href==='/account')return current==='/account'||current==='/pricing'||current==='/login';
    return path===current;
  }

  function installCustomerNavigation(){
    const current=cleanPath(location.pathname);
    const topLinks=[['/','Home'],['/scan','Scan'],['/reports','Activity'],['/dashboard','Workspace'],['/pricing','Plans']];
    const nav=document.querySelector('.koschei-global-nav')||document.querySelector('.top .nav,header.top nav.nav,nav.top .nav');
    if(nav){
      nav.classList.add('customer-nav-v3');
      nav.innerHTML='';
      for(const [href,label] of topLinks){
        const a=document.createElement('a');a.href=href;a.textContent=label;
        if(navActive(href,current))a.setAttribute('aria-current','page');
        nav.appendChild(a);
      }
    }
    if(!document.querySelector('.customer-mobile-nav-v3')){
      const mobile=document.createElement('nav');mobile.className='customer-mobile-nav-v3';mobile.setAttribute('aria-label','Customer navigation');
      const items=[['/','⌂','Home'],['/scan','⌕','Scan'],['/reports','≡','Activity'],['/account','○','Account']];
      for(const [href,icon,label] of items){
        const a=document.createElement('a');a.href=href;a.innerHTML=`<b aria-hidden="true">${icon}</b><span>${label}</span>`;
        if(navActive(href,current))a.setAttribute('aria-current','page');
        mobile.appendChild(a);
      }
      document.body.appendChild(mobile);
    }
  }

  function installReveal(){
    const nodes=[...document.querySelectorAll('[data-reveal]')];
    if(!nodes.length)return;
    if(!('IntersectionObserver'in window)){nodes.forEach(node=>node.classList.add('is-visible'));return;}
    const observer=new IntersectionObserver(entries=>entries.forEach(entry=>{
      if(!entry.isIntersecting)return;
      entry.target.classList.add('is-visible');
      observer.unobserve(entry.target);
    }),{rootMargin:'0px 0px -8% 0px',threshold:.08});
    nodes.forEach(node=>observer.observe(node));
  }

  async function hydrateHealth(){
    const indicators=[...document.querySelectorAll('[data-koschei-live]')];
    if(!indicators.length)return;
    const controller=new AbortController();
    const timer=window.setTimeout(()=>controller.abort('koschei_health_timeout'),HEALTH_TIMEOUT_MS);
    try{
      const response=await fetch('/health',{cache:'no-store',credentials:'same-origin',signal:controller.signal});
      const data=await response.json().catch(()=>({}));
      if(!response.ok)throw new Error(data.details||data.error||`HTTP ${response.status}`);
      const arvis=data.arvis||{};
      const status=String(arvis.pipeline_status||arvis.status||data.status||'ready').toLowerCase();
      const isLive=['ready','healthy','live','connected','ok','manual'].some(value=>status.includes(value));
      indicators.forEach(node=>{
        node.classList.toggle('is-live',isLive);
        node.dataset.koscheiDependencyState=isLive?'ready':'degraded';
        node.textContent=isLive?'ARVIS production pipeline ready':'DEGRADED · production pipeline could not be verified';
      });
    }catch(error){
      indicators.forEach(node=>{
        node.textContent='DEGRADED · evidence service unavailable';
        node.title=error?.name==='AbortError'?`Health check did not respond within ${HEALTH_TIMEOUT_MS/1000} seconds`:String(error?.message||'dependency error');
        node.dataset.koscheiDependencyState='degraded';
        node.classList.remove('is-live');
      });
    }finally{window.clearTimeout(timer);}
  }

  function installFormState(){
    document.querySelectorAll('form').forEach(form=>form.addEventListener('submit',()=>{
      document.body.classList.add('is-processing');
      window.setTimeout(()=>document.body.classList.remove('is-processing'),6000);
    }));
  }

  function installExternalSafety(){
    document.querySelectorAll('a[target="_blank"]').forEach(link=>{
      const rel=new Set(String(link.rel||'').split(/\s+/).filter(Boolean));
      rel.add('noopener');rel.add('noreferrer');link.rel=[...rel].join(' ');
    });
  }

  function installHomepageScan(){
    const form=document.querySelector('[data-koschei-home-scan]');if(!form)return;
    form.addEventListener('submit',event=>{
      const input=form.querySelector('input[name="target"]');
      if(!input||!input.value.trim()){event.preventDefault();input?.focus();return;}
      input.value=input.value.trim();
    });
  }

  function installCurrentNav(){
    const current=cleanPath(location.pathname);
    document.querySelectorAll('.koschei-global-nav a,.nav a').forEach(link=>{
      const path=cleanPath(new URL(link.href,location.origin).pathname);
      if(path===current)link.setAttribute('aria-current','page');
    });
  }

  installSurfaceStyles();
  ready(()=>{installCustomerNavigation();installReveal();hydrateHealth();installFormState();installExternalSafety();installHomepageScan();installCurrentNav();});
})();