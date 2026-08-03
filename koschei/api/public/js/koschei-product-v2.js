(()=>{
  'use strict';
  if(window.__koscheiProductV2)return;
  window.__koscheiProductV2=true;
  const ready=fn=>document.readyState==='loading'?document.addEventListener('DOMContentLoaded',fn,{once:true}):fn();
  const HEALTH_TIMEOUT_MS=10000;

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
    }finally{
      window.clearTimeout(timer);
    }
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
      rel.add('noopener');
      rel.add('noreferrer');
      link.rel=[...rel].join(' ');
    });
  }

  function installCurrentNav(){
    const current=(location.pathname||'/').replace(/\.html$/,'').replace(/\/$/,'')||'/';
    document.querySelectorAll('.koschei-global-nav a,.nav a').forEach(link=>{
      const path=(new URL(link.href,location.origin).pathname||'/').replace(/\.html$/,'').replace(/\/$/,'')||'/';
      if(path===current)link.setAttribute('aria-current','page');
    });
  }

  ready(()=>{installReveal();hydrateHealth();installFormState();installExternalSafety();installCurrentNav()});
})();